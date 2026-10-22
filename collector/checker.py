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
    sections += table('리소스 목록', report['resources'], ['profile', 'account', 'region', 'service', 'id', 'name', 'details'])
    metadata = html.escape(stringify({k: v for k, v in report.items() if k not in ('resources', 'findings', 'coverage')}))
    return '''<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SA AWS Resource Checker</title><style>
body{font:15px/1.6 'Segoe UI','Malgun Gothic',sans-serif;background:#f3f6fa;color:#18283e;margin:32px}h1{margin-bottom:0}h2{font-size:20px}.sub{color:#516174}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}.card,section{background:white;border:1px solid #dbe3ed;border-radius:12px;padding:18px}.card{min-width:100px}.card strong{display:block;font-size:28px;color:#1759ad}section{margin:20px 0}.scroll{overflow:auto;max-height:650px}table{border-collapse:collapse;width:100%;font-size:13px}th{background:#e9f0fa;text-align:left;position:sticky;top:0}td,th{padding:10px;border-bottom:1px solid #e1e7ef;vertical-align:top}td{min-width:95px;max-width:430px;overflow-wrap:anywhere;white-space:pre-wrap}input{width:min(600px,90%);padding:12px;border:1px solid #b6c6d9;border-radius:8px}details{margin-top:20px}pre{white-space:pre-wrap}.status{font-weight:700;color:#9b4500}
</style><h1>SA AWS Resource Checker</h1>''' + f'<p class="sub">{html.escape(report["mode"])} · {html.escape(report["started_at"])}</p>' + f'<p class="status">조회 상태: {html.escape(report["status"])} · 점검 후보 {len(report["findings"])}건</p>' + '''<p>오류가 있는 조회 항목은 미점검입니다. 후보 0건이 전체 정상 판정을 뜻하지 않습니다. SG 경고는 규칙만 평가하며 실제 외부 접근 가능성을 확정하지 않습니다.</p>
<input id="search" placeholder="프로필·계정·리전·리소스 검색" aria-label="결과 검색">''' + f'<div class="cards">{cards}</div>{sections}<details><summary>실행 정보</summary><pre>{metadata}</pre></details>' + '''<script>document.getElementById('search').addEventListener('input',e=>{const q=e.target.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q))})</script></html>'''


def export_report(report, out):
    out = Path(out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    folder = out / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6])
    folder.mkdir()
    (folder / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    (folder / 'report.html').write_text(html_report(report), encoding='utf-8')
    try:
        import xlsxwriter
        with xlsxwriter.Workbook(str(folder / 'report.xlsx'), {'strings_to_formulas': False, 'strings_to_urls': False}) as book:
            header = book.add_format({'bold': True, 'bg_color': '#DFEAF8', 'border': 1})
            wrap = book.add_format({'text_wrap': True, 'valign': 'top'})
            groups = [('Summary', [dict(metric=k, value=v) for k, v in {
                'mode': report['mode'], 'status': report['status'], 'resources': len(report['resources']),
                'findings': len(report['findings']), 'failed_queries': sum(x['status'] != 'OK' for x in report['coverage']),
                'started_at': report['started_at'], 'scope': stringify(report.get('requested_services', []))}.items()], ['metric', 'value']),
                ('Findings', report['findings'], ['severity', 'profile', 'account', 'region', 'service', 'id', 'rule', 'message', 'action', 'evidence']),
                ('Coverage', report['coverage'], ['profile', 'account', 'region', 'service', 'operation', 'status', 'count', 'error']),
                ('Inventory', report['resources'], ['profile', 'account', 'region', 'service', 'id', 'name', 'details'])]
            for name, rows, columns in groups:
                sheet = book.add_worksheet(name)
                sheet.freeze_panes(1, 0)
                sheet.set_column(0, len(columns)-1, 22, wrap)
                sheet.set_column(len(columns)-1, len(columns)-1, 70, wrap)
                for col, key in enumerate(columns):
                    sheet.write_string(0, col, key, header)
                for idx, row in enumerate(rows, 1):
                    for col, key in enumerate(columns):
                        value = row.get(key, '')
                        if isinstance(value, (int, float)) and not isinstance(value, bool):
                            sheet.write_number(idx, col, value)
                        else:
                            sheet.write_string(idx, col, stringify(value)[:32767])
                sheet.autofilter(0, 0, len(rows), len(columns)-1)
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
