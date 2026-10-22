"""SA AWS Resource Checker. Local read-only inventory and review rules."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import html
import ipaddress
import json
from pathlib import Path
import sys
import uuid

VERSION = '0.1.0'
# service, operation, result path, identifier
SPECS = {
    'EC2': ('ec2', 'describe_instances', 'Reservations.Instances', 'InstanceId'),
    'EBS': ('ec2', 'describe_volumes', 'Volumes', 'VolumeId'),
    'EIP': ('ec2', 'describe_addresses', 'Addresses', 'AllocationId'),
    'VPC': ('ec2', 'describe_vpcs', 'Vpcs', 'VpcId'),
    'Subnet': ('ec2', 'describe_subnets', 'Subnets', 'SubnetId'),
    'RouteTable': ('ec2', 'describe_route_tables', 'RouteTables', 'RouteTableId'),
    'SecurityGroup': ('ec2', 'describe_security_groups', 'SecurityGroups', 'GroupId'),
    'NAT': ('ec2', 'describe_nat_gateways', 'NatGateways', 'NatGatewayId'),
    'VPN': ('ec2', 'describe_vpn_connections', 'VpnConnections', 'VpnConnectionId'),
    'TGW': ('ec2', 'describe_transit_gateways', 'TransitGateways', 'TransitGatewayId'),
    'TGWAttachment': ('ec2', 'describe_transit_gateway_attachments', 'TransitGatewayAttachments', 'TransitGatewayAttachmentId'),
    'ELBv2': ('elbv2', 'describe_load_balancers', 'LoadBalancers', 'LoadBalancerArn'),
    'RDS': ('rds', 'describe_db_instances', 'DBInstances', 'DBInstanceIdentifier'),
    'Aurora': ('rds', 'describe_db_clusters', 'DBClusters', 'DBClusterIdentifier'),
    'ECS': ('ecs', 'list_clusters', 'clusterArns', None),
    'EKS': ('eks', 'list_clusters', 'clusters', None),
    'Lambda': ('lambda', 'list_functions', 'Functions', 'FunctionArn'),
}
SERVICES = list(SPECS) + ['S3', 'IAM']


def extract(page, path):
    values = [page]
    for part in path.split('.'):
        result = []
        for value in values:
            child = value.get(part, [])
            result.extend(child if isinstance(child, list) else [child])
        values = result
    return values


def pages(client, operation, **kwargs):
    """Streaming pagination preserves earlier pages if a later API fails."""
    if client.can_paginate(operation):
        yield from client.get_paginator(operation).paginate(**kwargs)
    else:
        yield getattr(client, operation)(**kwargs)


def resource(profile, account, region, service, identifier, data):
    name = next((t.get('Value', '') for t in data.get('Tags', [])
                 if t.get('Key') == 'Name'), '')
    return dict(profile=profile, account=account, region=region, service=service,
                id=str(identifier), name=name, details=data)


def evaluate(row):
    """Flags are review candidates, not compliance or reachability verdicts."""
    d, s = row['details'], row['service']
    findings = []

    def add(rule, severity, message, action, evidence):
        findings.append({k: row[k] for k in ('profile', 'account', 'region', 'service', 'id')} |
                        dict(rule=rule, severity=severity, message=message,
                             action=action, evidence=evidence))

    if s == 'EBS':
        if d.get('State') == 'available' and not d.get('Attachments'):
            add('EBS_UNUSED', 'REVIEW', '미연결 EBS 볼륨',
                '보관 목적과 백업을 확인한 뒤 정리 검토', 'State=available; Attachments=[]')
        if d.get('Encrypted') is False:
            add('EBS_ENCRYPTION', 'MEDIUM', 'EBS 암호화 미사용', '암호화 전환 검토', 'Encrypted=false')
    if s == 'EIP' and not d.get('AssociationId'):
        add('EIP_UNUSED', 'REVIEW', '연결되지 않은 Elastic IP', '예약 목적 및 필요성 확인', 'AssociationId 없음')
    if s == 'SecurityGroup':
        admin_ports = [22, 3389, 3306, 5432, 1433, 1521, 6379, 27017]
        for perm in d.get('IpPermissions', []):
            cidrs = [x.get('CidrIp') for x in perm.get('IpRanges', [])]
            cidrs += [x.get('CidrIpv6') for x in perm.get('Ipv6Ranges', [])]
            world = []
            for cidr in cidrs:
                try:
                    if ipaddress.ip_network(cidr).prefixlen == 0:
                        world.append(cidr)
                except (TypeError, ValueError):
                    continue
            proto = str(perm.get('IpProtocol'))
            ports = (admin_ports if proto == '-1' else
                     [p for p in admin_ports if perm.get('FromPort', -1) <= p <= perm.get('ToPort', -1)]
                     if proto in ('tcp', '6') else [])
            if world and ports:
                add('SG_ADMIN_WORLD', 'HIGH', '관리·DB 포트의 전체 인터넷 허용 규칙',
                    '연결 리소스·라우팅·NACL을 확인하고 허용 대역 제한',
                    json.dumps(dict(cidrs=world, protocol=proto, ports=ports)))
    if s in ('RDS', 'Aurora'):
        for field, rule, severity, message, action in [
            ('StorageEncrypted', 'RDS_ENCRYPTION', 'MEDIUM', 'DB 스토리지 암호화 미사용', '암호화 전환 방식 검토'),
            ('DeletionProtection', 'RDS_DELETE_PROTECTION', 'REVIEW', 'DB 삭제 방지 미사용', '운영 DB 여부 확인 후 삭제 방지 검토'),
            ('PubliclyAccessible', 'RDS_PUBLIC', 'HIGH', 'DB 공개 접근 설정 사용', 'SG·서브넷·라우팅을 함께 확인'),
        ]:
            expected = True if field == 'PubliclyAccessible' else False
            if d.get(field) is expected:
                add(rule, severity, message, action, f'{field}={expected}')
    if s == 'S3' and isinstance(d.get('PublicAccessBlock'), dict):
        block = d['PublicAccessBlock']
        if not all(block.get(k) is True for k in (
            'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')):
            add('S3_BUCKET_BPA', 'REVIEW', '버킷 수준 퍼블릭 액세스 차단 일부 미설정',
                '계정·조직 설정과 버킷 정책·ACL을 함께 확인. 공개 상태를 뜻하지 않음', json.dumps(block))
    if s == 'IAM' and d.get('AccountMFAEnabled') == 0:
        add('IAM_ROOT_MFA', 'HIGH', '루트 MFA 활성화 미확인',
            '중앙 관리 루트 자격 증명 제거 여부를 포함해 계정 보안 상태 확인', 'AccountMFAEnabled=0')
    return findings


def scan(profiles, regions, services=None, progress=print, session_factory=None, use_env=False):
    if session_factory is None:
        import boto3
        session_factory = boto3.Session
    from botocore.config import Config
    config = Config(retries={'mode': 'standard', 'total_max_attempts': 4},
                    connect_timeout=8, read_timeout=30)
    report = dict(version=VERSION, started_at=datetime.now(timezone.utc).isoformat(),
                  mode='LIVE', requested_profiles=profiles, requested_regions=regions,
                  requested_services=services or SERVICES, resources=[], findings=[], coverage=[])
    services = services or SERVICES

    def run(profile, account, region, label, operation, fn):
        progress(f'{profile} / {region} / {label} / {operation}')
        coverage = dict(profile=profile, account=account, region=region, service=label,
                        operation=operation, status='OK', count=0, error='')
        try:
            for row in fn():
                report['resources'].append(row)
                report['findings'].extend(evaluate(row))
                coverage['count'] += 1
        except Exception as exc:
            # Do not record raw exception messages that may contain sensitive values.
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
            coverage.update(status='PARTIAL' if coverage['count'] else 'ERROR', error=str(code))
            progress(f'  {coverage["status"]}: {code}')
        report['coverage'].append(coverage)

    for profile in profiles:
        try:
            session = session_factory(profile_name=None if use_env else profile, region_name='ap-northeast-2')
            account = session.client('sts', config=config).get_caller_identity()['Account']
        except Exception as exc:
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
            report['coverage'].append(dict(profile=profile, account='', region='global',
                service='STS', operation='get_caller_identity', status='ERROR', count=0, error=code))
            continue
        selected_regions = regions
        if regions == ['all']:
            try:
                selected_regions = sorted(x['RegionName'] for x in session.client('ec2', config=config)
                                          .describe_regions(AllRegions=False)['Regions'])
                report['coverage'].append(dict(profile=profile, account=account, region='global',
                    service='Regions', operation='describe_regions', status='OK',
                    count=len(selected_regions), error=''))
            except Exception as exc:
                code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
                report['coverage'].append(dict(profile=profile, account=account, region='global',
                    service='Regions', operation='describe_regions', status='ERROR', count=0, error=code))
                selected_regions = []
        for region in selected_regions:
            for label in services:
                if label not in SPECS:
                    continue
                sdk, operation, path, key = SPECS[label]

                def collect(sdk=sdk, operation=operation, path=path, key=key, label=label):
                    client = session.client(sdk, region_name=region, config=config)
                    for page in pages(client, operation):
                        for value in extract(page, path):
                            data = dict(value) if isinstance(value, dict) else {'Value': value}
                            if label == 'Lambda':
                                environment = data.pop('Environment', None)
                                if isinstance(environment, dict):
                                    data['EnvironmentVariableNames'] = sorted(environment.get('Variables', {}))
                            identifier = data.get(key, '') if key else value
                            yield resource(profile, account, region, label, identifier, data)
                run(profile, account, region, label, operation, collect)
        if 'IAM' in services:
            def collect_iam():
                data = session.client('iam', config=config).get_account_summary()['SummaryMap']
                yield resource(profile, account, 'global', 'IAM', account, data)
            run(profile, account, 'global', 'IAM', 'get_account_summary', collect_iam)
        if 'S3' in services:
            # List first; detail errors never erase inventory rows.
            def collect_buckets():
                client = session.client('s3', config=config)
                for page in pages(client, 'list_buckets'):
                    for bucket in page.get('Buckets', []):
                        yield resource(profile, account, 'global', 'S3', bucket['Name'], bucket)
            before = len(report['resources'])
            run(profile, account, 'global', 'S3', 'list_buckets', collect_buckets)
            buckets = report['resources'][before:]
            for bucket in buckets:
                bucket_name = bucket['id']
                def collect_s3_detail():
                    # Region can be supplied directly by current ListBuckets responses.
                    client = session.client('s3', region_name='us-east-1', config=config)
                    location = client.get_bucket_location(Bucket=bucket_name).get('LocationConstraint')
                    location = {'EU': 'eu-west-1', None: 'us-east-1'}.get(location, location)
                    bucket['region'] = location
                    regional = session.client('s3', region_name=location, config=config)
                    try:
                        block = regional.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                    except Exception as exc:
                        if getattr(exc, 'response', {}).get('Error', {}).get('Code') != 'NoSuchPublicAccessBlockConfiguration':
                            raise
                        block = {k: False for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')}
                    bucket['details']['PublicAccessBlock'] = block
                    report['findings'].extend(evaluate(bucket))
                    return iter(())
                run(profile, account, 'global', 'S3', f'bucket_detail:{bucket_name}', collect_s3_detail)
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    report['status'] = 'INCOMPLETE' if any(x['status'] != 'OK' for x in report['coverage']) else 'COMPLETE'
    return report


def demo():
    report = dict(version=VERSION, mode='DEMO / 가상 데이터', status='INCOMPLETE',
                  started_at=datetime.now(timezone.utc).isoformat(),
                  requested_profiles=['demo'], requested_regions=['ap-northeast-2'],
                  requested_services=['EBS', 'SecurityGroup', 'RDS'], resources=[], findings=[], coverage=[])
    fixtures = [('EBS', 'vol-demo', {'State': 'available', 'Attachments': [], 'Encrypted': True}),
                ('SecurityGroup', 'sg-demo', {'IpPermissions': [{'IpProtocol': 'tcp', 'FromPort': 22,
                    'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]}),
                ('RDS', 'db-demo', {'PubliclyAccessible': False, 'StorageEncrypted': True, 'DeletionProtection': False})]
    for service, identifier, data in fixtures:
        row = resource('demo', '000000000000', 'ap-northeast-2', service, identifier, data)
        report['resources'].append(row)
        report['findings'].extend(evaluate(row))
        report['coverage'].append(dict(profile='demo', account='000000000000', region='ap-northeast-2',
            service=service, operation='demo', status='OK', count=1, error=''))
    report['coverage'].append(dict(profile='demo', account='000000000000', region='ap-northeast-2',
        service='EKS', operation='demo', status='ERROR', count=0, error='AccessDenied (가상)'))
    report['finished_at'] = report['started_at']
    return report


def stringify(value):
    return json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)


def html_report(report):
    def table(title, rows, columns):
        head = ''.join(f'<th>{html.escape(c)}</th>' for c in columns)
        body = ''.join('<tr>' + ''.join(f'<td>{html.escape(stringify(r.get(c, "")))}</td>' for c in columns) + '</tr>' for r in rows)
        return f'<section><h2>{title} ({len(rows)})</h2><div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div></section>'
    counts = Counter(r['service'] for r in report['resources'])
    cards = ''.join(f'<div class="card"><b>{html.escape(k)}</b><strong>{v}</strong></div>' for k, v in sorted(counts.items()))
    sections = table('점검 후보', report['findings'], ['severity', 'profile', 'account', 'region', 'service', 'id', 'message', 'action', 'evidence'])
    sections += table('조회 범위와 오류', report['coverage'], ['profile', 'account', 'region', 'service', 'operation', 'status', 'count', 'error'])
    sections += table('리소스 목록', report['resources'], ['profile', 'account', 'region', 'service', 'id', 'name'])
    metadata = html.escape(stringify({k: v for k, v in report.items() if k not in ('resources', 'findings', 'coverage')}))
    return '''<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SA AWS Resource Checker</title><style>
body{font:15px/1.6 'Segoe UI','Malgun Gothic',sans-serif;background:#f3f6fa;color:#18283e;margin:32px}h1{margin-bottom:0}h2{font-size:20px}.sub{color:#516174}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}.card,section{background:white;border:1px solid #dbe3ed;border-radius:12px;padding:18px}.card{min-width:100px}.card strong{display:block;font-size:28px;color:#1759ad}section{margin:20px 0}.scroll{overflow:auto;max-height:650px}table{border-collapse:collapse;width:100%;font-size:13px}th{background:#e9f0fa;text-align:left;position:sticky;top:0}td,th{padding:10px;border-bottom:1px solid #e1e7ef;vertical-align:top}td{min-width:95px;max-width:430px;overflow-wrap:anywhere;white-space:pre-wrap}input{width:min(600px,90%);padding:12px;border:1px solid #b6c6d9;border-radius:8px}details{margin-top:20px}pre{white-space:pre-wrap}.status{font-weight:700;color:#9b4500}
</style><h1>SA AWS Resource Checker</h1>''' + f'<p class="sub">{html.escape(report["mode"])} · {html.escape(report["started_at"])}</p>' + f'<p class="status">조회 상태: {html.escape(report["status"])} · 점검 후보 {len(report["findings"])}건</p>' + '''<p>오류가 있는 조회 항목은 미점검입니다. 후보 0건이 전체 정상 판정을 뜻하지 않습니다. SG 경고는 규칙만 평가하며 실제 외부 접근 가능성을 확정하지 않습니다.</p>
<input id="search" placeholder="프로필·계정·리전·리소스 검색" aria-label="결과 검색">''' + f'<div class="cards">{cards}</div>{sections}<details><summary>실행 정보</summary><pre>{metadata}</pre></details>' + '''<script>document.getElementById('search').addEventListener('input',e=>{const q=e.target.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q))})</script></html>'''


def inventory_fields(service, data):
    """Return short, typed service attributes; never stringify the raw payload."""
    def get(path):
        value = data
        for part in path.split('.'):
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    def flag(path):
        value = get(path)
        return '사용' if value is True else '미사용' if value is False else '미확인'

    def joined(path, key):
        return ', '.join(str(x.get(key, '')) for x in (get(path) or []) if isinstance(x, dict) and x.get(key)) or '—'

    fields = {
        'EC2': [('상태', get('State.Name')), ('인스턴스 타입', get('InstanceType')),
                ('가용 영역', get('Placement.AvailabilityZone')), ('사설 IP', get('PrivateIpAddress')),
                ('공인 IP', get('PublicIpAddress')), ('VPC', get('VpcId')), ('서브넷', get('SubnetId'))],
        'EBS': [('상태', get('State')), ('볼륨 타입', get('VolumeType')), ('용량 (GiB)', get('Size')),
                ('암호화', flag('Encrypted')), ('연결 인스턴스', joined('Attachments', 'InstanceId'))],
        'EIP': [('공인 IP', get('PublicIp')), ('사설 IP', get('PrivateIpAddress')),
                ('연결 ID', get('AssociationId')), ('인스턴스', get('InstanceId'))],
        'RDS': [('상태', get('DBInstanceStatus')), ('엔진', get('Engine')), ('버전', get('EngineVersion')),
                ('DB 클래스', get('DBInstanceClass')), ('용량 (GiB)', get('AllocatedStorage')),
                ('Multi-AZ', flag('MultiAZ')), ('암호화', flag('StorageEncrypted')),
                ('삭제 방지', flag('DeletionProtection'))],
        'Aurora': [('상태', get('Status')), ('엔진', get('Engine')), ('버전', get('EngineVersion')),
                   ('엔진 모드', get('EngineMode')), ('멤버 수', len(get('DBClusterMembers')) if isinstance(get('DBClusterMembers'), list) else None),
                   ('암호화', flag('StorageEncrypted')), ('삭제 방지', flag('DeletionProtection'))],
        'VPC': [('상태', get('State')), ('CIDR', get('CidrBlock')), ('기본 VPC', flag('IsDefault'))],
        'Subnet': [('상태', get('State')), ('CIDR', get('CidrBlock')), ('가용 영역', get('AvailabilityZone')),
                   ('사용 가능 IP 수', get('AvailableIpAddressCount')), ('VPC', get('VpcId'))],
        'RouteTable': [('VPC', get('VpcId')), ('라우트 수', len(get('Routes')) if isinstance(get('Routes'), list) else None)],
        'SecurityGroup': [('그룹 이름', get('GroupName')), ('VPC', get('VpcId')),
                          ('인바운드 규칙 수', len(get('IpPermissions')) if isinstance(get('IpPermissions'), list) else None),
                          ('아웃바운드 규칙 수', len(get('IpPermissionsEgress')) if isinstance(get('IpPermissionsEgress'), list) else None)],
        'NAT': [('상태', get('State')), ('연결 유형', get('ConnectivityType')), ('VPC', get('VpcId')),
                ('서브넷', get('SubnetId')), ('공인 IP', joined('NatGatewayAddresses', 'PublicIp'))],
        'VPN': [('상태', get('State')), ('유형', get('Type')), ('VGW', get('VpnGatewayId')),
                ('TGW', get('TransitGatewayId')), ('고객 게이트웨이', get('CustomerGatewayId'))],
        'TGW': [('상태', get('State')), ('Amazon ASN', get('Options.AmazonSideAsn'))],
        'TGWAttachment': [('상태', get('State')), ('리소스 유형', get('ResourceType')),
                          ('연결 리소스', get('ResourceId')), ('TGW', get('TransitGatewayId'))],
        'ELBv2': [('상태', get('State.Code')), ('유형', get('Type')), ('공개 범위', get('Scheme')),
                  ('DNS', get('DNSName')), ('VPC', get('VpcId'))],
        'Lambda': [('상태', get('State')), ('런타임', get('Runtime')), ('메모리 (MB)', get('MemorySize')),
                   ('타임아웃 (초)', get('Timeout')), ('최종 수정', get('LastModified'))],
        'S3': [('퍼블릭 차단', '모두 설정' if isinstance(get('PublicAccessBlock'), dict) and all(get('PublicAccessBlock').get(k) is True for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')) else '일부 미설정' if isinstance(get('PublicAccessBlock'), dict) else '미확인')],
        'IAM': [('사용자 수', get('Users')), ('역할 수', get('Roles')), ('그룹 수', get('Groups')),
                ('루트 MFA', '활성' if get('AccountMFAEnabled') == 1 else '미활성/제거 여부 확인' if get('AccountMFAEnabled') == 0 else '미확인')],
        'EKS': [('수집 범위', '클러스터 목록')],
        'ECS': [('수집 범위', '클러스터 목록')],
    }
    return fields.get(service, [])


def excel_report(report, path):
    """Visual Excel export for the existing Python/CloudShell application."""
    import xlsxwriter
    resources, findings, coverage = (report[k] for k in ('resources', 'findings', 'coverage'))
    groups = {}
    for row in resources:
        groups.setdefault(row['service'], []).append(row)
    requested = set(report.get('requested_services', [])) | set(groups)
    requested.update(x['service'] for x in coverage if x['service'] not in ('STS', 'Regions'))
    services = sorted(requested, key=lambda s: (-len(groups.get(s, [])), s))
    per_service = Counter(x['service'] for x in findings)
    per_resource = Counter((x.get('profile'), x.get('account'), x.get('region'), x.get('service'), x.get('id')) for x in findings)
    failures = [x for x in coverage if x['status'] != 'OK']

    def state(service):
        queries = [x for x in coverage if x['service'] == service]
        if not queries:
            return '미조회'
        if any(x['status'] != 'OK' for x in queries):
            return '부분 실패' if any(x['status'] == 'OK' for x in queries) or groups.get(service) else '조회 실패'
        return '조회 완료'

    with xlsxwriter.Workbook(str(path), {'strings_to_formulas': False, 'strings_to_urls': False}) as book:
        base = {'font_name': 'Malgun Gothic', 'font_size': 10, 'font_color': '#24364B', 'valign': 'vcenter'}
        body = book.add_format(base)
        number = book.add_format(base | {'num_format': '#,##0'})
        title = book.add_format(base | {'font_size': 16, 'bold': True})
        note = book.add_format(base | {'font_color': '#63758B'})
        heading = book.add_format(base | {'bg_color': '#203B60', 'font_color': '#FFFFFF', 'bold': True, 'align': 'center', 'text_wrap': True})
        link = book.add_format(base | {'font_color': '#2463C9', 'underline': 1})
        warning = book.add_format(base | {'bg_color': '#FFF3DF', 'font_color': '#9C5700'})
        danger = book.add_format(base | {'bg_color': '#FDE9E7', 'font_color': '#A62D26', 'bold': True})
        good = book.add_format(base | {'bg_color': '#EAF5F1', 'font_color': '#236C58'})
        summary = book.add_worksheet('Summary')
        summary.set_tab_color('#203B60')
        used_names = {'summary', 'findings', 'coverage', 'inventory'}
        service_sheets = {}
        import re
        for index, service in enumerate(services):
            name = re.sub(r"[\[\]:*?/\\']", '_', service)[:31] or f'Service{index+1}'
            if name.lower() in used_names:
                name = f'Service{index+1}'
            used_names.add(name.lower())
            service_sheets[service] = book.add_worksheet(name)
        find_sheet = book.add_worksheet('Findings')
        cover_sheet = book.add_worksheet('Coverage')
        inventory = book.add_worksheet('Inventory')

        def setup(sheet, subtitle, width=24):
            sheet.hide_gridlines(2)
            sheet.set_default_row(24)
            sheet.set_column(0, 16, width, body)
            sheet.set_landscape()
            sheet.fit_to_pages(1, 0)
            sheet.set_paper(9)
            sheet.write_string(1, 0, subtitle, title)
            sheet.set_row(1, 32)
            sheet.set_footer('&L AWS Resource Checker &R &P / &N')
            sheet.write_url(3, 0, "internal:'Summary'!A1", link, '요약으로 돌아가기')

        def write_table(sheet, headers, rows, table_name):
            sheet.set_row(6, 32)
            if rows:
                sheet.add_table(6, 0, 6 + len(rows), len(headers)-1, {
                    'name': table_name, 'style': 'Table Style Medium 2',
                    'columns': [{'header': h, 'header_format': heading} for h in headers], 'data': rows})
            else:
                for col, h in enumerate(headers):
                    sheet.write_string(6, col, h, heading)
                sheet.write_string(7, 0, '수집된 항목 없음. Summary와 Coverage에서 조회 범위를 확인하세요.', note)
            sheet.freeze_panes(7, min(3, len(headers)))
            sheet.repeat_rows(6)
            sheet.print_area(0, 0, max(8, 6+len(rows)), len(headers)-1)

        setup(summary, 'AWS 리소스 현황')
        summary.write_string(3, 0, f"{report['started_at']}   {report['mode']}   상태: {report['status']}", note)
        summary.set_column('A:A', 23)
        summary.set_column('B:D', 13)
        summary.set_column('E:E', 16)
        summary.set_column('F:F', 18)
        summary.set_column('G:G', 3)
        summary.set_column('H:N', 11)
        labels = ['수집 리소스', '점검 후보', '실패·부분 조회', '조회 계정']
        counts = [len(resources), len(findings), len(failures), len({x.get('account') for x in resources+coverage if x.get('account')})]
        for col, label, value in zip((0, 4, 8, 11), labels, counts):
            cardlabel = book.add_format(base | {'font_color': '#63758B', 'bg_color': '#F0F4FA'})
            cardvalue = book.add_format(base | {'font_size': 16, 'bold': True, 'bg_color': '#F0F4FA', 'num_format': '#,##0'})
            summary.merge_range(5, col, 5, col+2, label, cardlabel)
            summary.merge_range(6, col, 7, col+2, value, cardvalue)
        summary.merge_range('A10:N10', '집계 단위는 수집 항목입니다. EKS/ECS는 클러스터 목록, IAM은 계정 요약입니다. 조회 실패·미조회는 리소스 없음으로 판단하지 않습니다.', note)
        summary.set_row(9, 25)
        headers = ['서비스', '리소스 수', '점검 후보', '실패 조회', '조회 상태', '리소스 목록']
        for col,h in enumerate(headers):
            summary.write_string(11,col,h,heading)
        summary.set_row(11,30)
        for rownum,service in enumerate(services,12):
            sheet=service_sheets[service]
            summary.write_string(rownum,0,service,body)
            summary.write_number(rownum,1,len(groups.get(service,[])),number)
            summary.write_number(rownum,2,per_service[service],number)
            summary.write_number(rownum,3,sum(x['service']==service for x in failures),number)
            summary.write_string(rownum,4,state(service),body)
            summary.write_url(rownum,5,f"internal:'{sheet.name}'!A1",link,'목록 열기')
        if services:
            end=11+len(services)
            summary.conditional_format(12,1,end,1,{'type':'data_bar','bar_color':'#4D83C8'})
            for col in (2,3):
                summary.conditional_format(12,col,end,col,{'type':'cell','criteria':'>','value':0,'format':warning})
            for text,fmt in [('조회 실패',danger),('부분 실패',warning),('미조회',warning)]:
                summary.conditional_format(12,4,end,4,{'type':'text','criteria':'containing','value':text,'format':fmt})
        chart_rows = [i for i,s in enumerate(services) if groups.get(s)][:12]
        if chart_rows:
            chart=book.add_chart({'type':'bar'})
            last=12+len(chart_rows)-1
            chart.add_series({'name':'리소스 수','categories':['Summary',12,0,last,0],
                              'values':['Summary',12,1,last,1],'fill':{'color':'#3A76C5'},
                              'border':{'none':True},'data_labels':{'value':True,'font':{'name':'Malgun Gothic','size':10}}})
            chart.set_title({'name':'서비스별 리소스 수 (상위 12개)','name_font':{'name':'Malgun Gothic','size':12}})
            chart.set_legend({'none':True})
            chart.set_x_axis({'min':0,'num_format':'0','name_font':{'name':'Malgun Gothic'},'num_font':{'name':'Malgun Gothic','size':10}})
            chart.set_y_axis({'reverse':True,'num_font':{'name':'Malgun Gothic','size':10}})
            chart.set_size({'width':580,'height':390})
            chart.set_chartarea({'border':{'none':True}})
            summary.insert_chart('H12',chart)
        else:
            summary.write_string(12,7,'수집된 리소스가 없습니다. Coverage에서 오류를 확인하세요.',note)
        summary.freeze_panes(12,1)
        summary.print_area(0,0,max(33,13+len(services)),13)
        summary.write_url(max(33,14+len(services)),0,"internal:'Coverage'!A1",link,'조회 범위·오류 확인')
        summary.write_url(max(33,14+len(services)),4,"internal:'Findings'!A1",link,'점검 후보 확인')

        common=['AWS 계정','리전','리소스 ID','이름','점검 후보 수']
        for index,service in enumerate(services):
            sheet=service_sheets[service]
            rows=groups.get(service,[])
            setup(sheet,f'{service} 리소스 목록')
            sheet.write_string(4,0,f'수집 {len(rows):,}개 / 점검 후보 {per_service[service]:,}건 / {state(service)}',note)
            extra=inventory_fields(service,{})
            values=[]
            for row in rows:
                identity=tuple(row.get(k) for k in ('profile','account','region','service','id'))
                values.append([row.get('account',''),row.get('region',''),row.get('id',''),row.get('name',''),per_resource[identity]]+
                              [v if v is not None else '미확인' for _,v in inventory_fields(service,row.get('details') or {})])
            write_table(sheet,common+[h for h,_ in extra],values,f'ServiceTable{index+1}')
            sheet.set_column(0,0,17,body)
            sheet.set_column(1,1,20,body)
            sheet.set_column(2,2,44,body)
            sheet.set_column(3,3,30,body)
            sheet.set_column(4,4,15,number)
            for col,(label,_) in enumerate(extra,5):
                sheet.set_column(col,col,28 if label in ('인스턴스 타입','DB 클래스','가용 영역','연결 인스턴스') else 23,body)
            if rows:
                sheet.conditional_format(7,4,6+len(rows),4,{'type':'cell','criteria':'>','value':0,'format':warning})
                if extra and extra[0][0]=='상태':
                    for status in ('running','available','active','in-use'):
                        sheet.conditional_format(7,5,6+len(rows),5,{'type':'cell','criteria':'equal to','value':f'"{status}"','format':good})
                    for status in ('stopped','failed','error'):
                        sheet.conditional_format(7,5,6+len(rows),5,{'type':'cell','criteria':'equal to','value':f'"{status}"','format':warning})

        specs=[
            (find_sheet,'점검 후보',['중요도','서비스','AWS 계정','리전','리소스 ID','점검 내용','확인할 사항','근거'],
             [[x.get(k,'') for k in ('severity','service','account','region','id','message','action','evidence')] for x in findings],'FindingsTable'),
            (cover_sheet,'조회 범위와 오류',['조회 상태','서비스','AWS 계정','리전','조회 API','수집 수','오류 코드'],
             [[x.get(k,'') for k in ('status','service','account','region','operation','count','error')] for x in coverage],'CoverageTable'),
            (inventory,'전체 리소스 목록',['서비스','AWS 계정','리전','리소스 ID','이름'],
             [[x.get(k,'') for k in ('service','account','region','id','name')] for x in resources],'InventoryTable')]
        for sheet,label,headers,rows,name in specs:
            setup(sheet,label)
            values=[[stringify(v)[:32767] if isinstance(v,(dict,list)) else v for v in row] for row in rows]
            write_table(sheet,headers,values,name)
            sheet.set_column(0,0,20,body)
            sheet.set_column(1,3,22,body)
            sheet.set_column(4,len(headers)-1,40,body)
            if sheet==find_sheet and rows:
                sheet.set_column(5,7,50,book.add_format(base|{'text_wrap':True,'valign':'top'}))
                for rownum in range(7,7+len(rows)):
                    sheet.set_row(rownum,48)
                for severity,fmt in [('HIGH',danger),('MEDIUM',warning),('REVIEW',warning)]:
                    sheet.conditional_format(7,0,6+len(rows),0,{'type':'text','criteria':'containing','value':severity,'format':fmt})
            if sheet==cover_sheet and rows:
                for status,fmt in [('ERROR',danger),('PARTIAL',warning)]:
                    sheet.conditional_format(7,0,6+len(rows),0,{'type':'text','criteria':'containing','value':status,'format':fmt})
        summary.activate()
        summary.set_first_sheet()


def export_report(report, out):
    out = Path(out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    folder = out / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6])
    folder.mkdir()
    (folder / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    (folder / 'report.html').write_text(html_report(report), encoding='utf-8')
    try:
        excel_report(report, folder / 'report.xlsx')
    except ImportError:
        print('Excel 출력 생략: xlsxwriter를 설치하세요. HTML·JSON은 저장되었습니다.')
    return folder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument('--profiles', nargs='+', default=['default'])
    auth.add_argument('--use-env', action='store_true', help='Use SDK credential chain, including Actions OIDC environment credentials')
    parser.add_argument('--regions', nargs='+', default=['ap-northeast-2'], help='리전 목록 또는 all')
    parser.add_argument('--services', nargs='+', choices=SERVICES)
    parser.add_argument('--out', default='reports')
    parser.add_argument('--demo', action='store_true')
    args = parser.parse_args()
    if 'all' in args.regions and args.regions != ['all']:
        parser.error('all은 단독으로 지정하세요.')
    try:
        report = demo() if args.demo else scan(['github-oidc'] if args.use_env else args.profiles,
                                              args.regions, args.services, use_env=args.use_env)
        folder = export_report(report, args.out)
        print(f'{report["status"]}: {folder}')
        return 0 if args.demo or report['status'] == 'COMPLETE' else 2
    except Exception as exc:
        print(f'실행 실패: {type(exc).__name__}. 의존성·프로필·출력 경로를 확인하세요.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
