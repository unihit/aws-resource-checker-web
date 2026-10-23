"""Offline Well-Architected heuristics over Resource Checker snapshots.

No SDK, credentials, network, storage, scoring, or extra AWS permissions.
Existing resources/findings/coverage are inputs and are never modified.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path

RULESET = '2026-10-23.1'
PILLARS = {
    'OPS': 'Operational Excellence', 'SEC': 'Security', 'REL': 'Reliability',
    'PERF': 'Performance Efficiency', 'COST': 'Cost Optimization', 'SUS': 'Sustainability',
}
SLUGS = dict(OPS='operational-excellence', SEC='security', REL='reliability',
             PERF='performance-efficiency', COST='cost-optimization', SUS='sustainability')
STATUSES = ('FAIL', 'UNKNOWN', 'MANUAL', 'EXCEPTION', 'PASS', 'NOT_APPLICABLE')


def boolean(value, expected=True):
    return value == expected if type(value) is bool else None


def number(value, condition):
    return condition(value) if type(value) in (int, float) else None


def value(data, path):
    for key in path.split('.'):
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def evidence_value(data, path):
    observed = value(data, path)
    if path == 'IpPermissions' and isinstance(observed, list):
        return [{k:p.get(k) for k in ('IpProtocol','FromPort','ToPort') if k in p} |
                {group:[{key:item.get(key)} for item in p.get(group,[]) if isinstance(item,dict)]
                 for group,key in (('IpRanges','CidrIp'),('Ipv6Ranges','CidrIpv6')) if isinstance(p.get(group),list)}
                for p in observed if isinstance(p,dict)]
    if path == 'Attachments' and isinstance(observed,list):
        return {'count':len(observed)}
    if path == 'AvailabilityZones' and isinstance(observed,list):
        return [{'ZoneName':item.get('ZoneName')} for item in observed if isinstance(item,dict)]
    return observed


def admin_closed(data):
    permissions = data.get('IpPermissions')
    if not isinstance(permissions, list):
        return None
    unknown = False
    for p in permissions:
        if not isinstance(p, dict) or not isinstance(p.get('IpProtocol'), str):
            unknown = True
            continue
        world = False
        for group, key in [('IpRanges', 'CidrIp'), ('Ipv6Ranges', 'CidrIpv6')]:
            ranges = p.get(group, [])
            if not isinstance(ranges, list):
                unknown = True
                continue
            for item in ranges:
                try:
                    world |= ipaddress.ip_network(item[key]).prefixlen == 0
                except (KeyError, TypeError, ValueError):
                    unknown = True
        if not world:
            continue
        if p['IpProtocol'] == '-1':
            return False
        if p['IpProtocol'] in ('tcp', '6'):
            start, end = p.get('FromPort'), p.get('ToPort')
            if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
                unknown = True
            elif any(start <= port <= end for port in (22, 3389, 3306, 5432, 1433, 1521, 6379, 27017)):
                return False
    return None if unknown else True


def bpa(data):
    block = data.get('PublicAccessBlock')
    keys = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')
    if not isinstance(block, dict) or not all(type(block.get(k)) is bool for k in keys):
        return None
    return all(block[k] for k in keys)


def multi_az(data):
    if not isinstance(data.get('Engine'), str) or data['Engine'].startswith('aurora'):
        return None
    return boolean(data.get('MultiAZ'))


def azs(data):
    zones = data.get('AvailabilityZones')
    if not isinstance(zones, list) or any(not isinstance(x, dict) or not isinstance(x.get('ZoneName'), str) for x in zones):
        return None
    return len({x['ZoneName'] for x in zones}) >= 2


def unused_volume(data):
    state, attachments = data.get('State'), data.get('Attachments')
    if state not in ('creating', 'available', 'in-use', 'deleting', 'deleted', 'error') or not isinstance(attachments, list):
        return None
    return not (state == 'available' and not attachments)


def monitoring(data):
    state = value(data, 'State.Name')
    if state in ('pending', 'stopping', 'stopped', 'shutting-down', 'terminated'):
        return 'NOT_APPLICABLE'
    mode = value(data, 'Monitoring.State')
    return mode == 'enabled' if state == 'running' and mode in ('enabled', 'disabled', 'pending', 'disabling') else None


# id, pillar, service, title, severity, fields, predicate, recommendation, existing rule ID
RULES = [
    ('SEC-001', 'SEC', 'EBS', 'EBS 암호화', 'MEDIUM', ('Encrypted',), lambda d: boolean(d.get('Encrypted')),
     '암호화 전환 방식을 검토하세요.', 'EBS_ENCRYPTION'),
    ('SEC-002', 'SEC', 'SecurityGroup', '관리·DB 포트의 전체 인터넷 허용 규칙', 'HIGH', ('IpPermissions',), admin_closed,
     '연결 리소스·라우팅·NACL과 허용 대역을 확인하세요. 실제 인터넷 도달성을 확정하지 않습니다.', 'SG_ADMIN_WORLD'),
    ('SEC-003', 'SEC', 'RDS', 'DB 스토리지 암호화', 'MEDIUM', ('StorageEncrypted',), lambda d: boolean(d.get('StorageEncrypted')),
     '엔진별 암호화 전환 방식을 검토하세요.', 'RDS_ENCRYPTION'),
    ('SEC-004', 'SEC', 'RDS', 'DB 공개 접근 설정', 'HIGH', ('PubliclyAccessible',), lambda d: boolean(d.get('PubliclyAccessible'), False),
     'SG·서브넷·라우팅과 공개 접근 필요성을 함께 확인하세요.', 'RDS_PUBLIC'),
    ('SEC-005', 'SEC', 'S3', '버킷 수준 공개 차단 4종', 'MEDIUM', ('PublicAccessBlock',), bpa,
     '버킷·계정·조직 설정과 정책·ACL을 확인하세요. 이 규칙만으로 실제 공개를 확정하지 않습니다.', 'S3_BUCKET_BPA'),
    ('SEC-006', 'SEC', 'IAM', '루트 MFA 활성화', 'HIGH', ('AccountMFAEnabled',), lambda d: number(d.get('AccountMFAEnabled'), lambda n:n == 1),
     'Organizations 중앙 루트 자격증명 제거 여부를 포함해 계정 보안 상태를 확인하세요.', 'IAM_ROOT_MFA'),
    ('SEC-007', 'SEC', 'IAM', '루트 액세스 키 부재', 'HIGH', ('AccountAccessKeysPresent',), lambda d: number(d.get('AccountAccessKeysPresent'), lambda n:n == 0),
     '루트 키 사용 필요성을 확인하고 제거 계획을 검토하세요.', ''),
    ('REL-001', 'REL', 'RDS', 'RDS Multi-AZ', 'MEDIUM', ('Engine', 'MultiAZ'), multi_az,
     'RTO/RPO에 맞춰 다중 AZ를 검토하세요. Aurora는 클러스터·리더 배치를 수동 확인하세요.', ''),
    ('REL-002', 'REL', 'RDS', 'DB 자동 백업 보존 7일 이상', 'MEDIUM', ('BackupRetentionPeriod',), lambda d:number(d.get('BackupRetentionPeriod'), lambda n:n >= 7),
     '7일은 본 도구의 검토 기준입니다. 업무 RPO·규정과 복원 테스트로 적합성을 확인하세요.', ''),
    ('REL-003', 'REL', 'RDS', 'DB 삭제 방지', 'LOW', ('DeletionProtection',), lambda d:boolean(d.get('DeletionProtection')),
     '운영 DB인지 확인하고 삭제 방지 필요성을 검토하세요.', 'RDS_DELETE_PROTECTION'),
    ('REL-004', 'REL', 'ELBv2', 'ELB 가용 영역 2개 이상', 'MEDIUM', ('AvailabilityZones', 'Type'), azs,
     '워크로드 가용성 요구에 맞춰 다중 AZ와 백엔드 배치를 검토하세요.', ''),
    ('PERF-001', 'PERF', 'EBS', 'gp2 볼륨 현대화 후보', 'LOW', ('VolumeType',), lambda d:d['VolumeType'] != 'gp2' if isinstance(d.get('VolumeType'), str) and d['VolumeType'] else None,
     'gp3 전환 전 IOPS·처리량·지연과 비용을 비교하세요. gp2가 성능 장애라는 뜻은 아닙니다.', ''),
    ('PERF-002', 'PERF', 'EC2', '실행 중 EC2 상세 모니터링', 'LOW', ('State.Name', 'Monitoring.State'), monitoring,
     '관측 주기와 상세 모니터링 추가 비용을 비교하세요. 기본 모니터링이 충분한지 수동 확인하세요.', ''),
    ('COST-001', 'COST', 'EBS', '미연결 EBS 보존 목적', 'LOW', ('State', 'Attachments'), unused_volume,
     '소유자·복구·보존 목적을 확인한 뒤 정리 여부를 결정하세요. 리소스를 자동 삭제하지 않습니다.', 'EBS_UNUSED'),
    ('SUS-001', 'SUS', 'EC2', '중지된 EC2 잔존 리소스 검토', 'LOW', ('State.Name',), lambda d:value(d,'State.Name') != 'stopped' if value(d,'State.Name') in ('pending','running','stopping','stopped','shutting-down','terminated') else None,
     '중지 목적과 연결 볼륨 등을 확인하세요. 중지된 EC2 자체의 컴퓨팅 요금이나 탄소량을 추정하지 않습니다.', ''),
]
UNAVAILABLE = [
    ('OPS-001', 'OPS', 'CloudTrail', 'CloudTrail 실제 기록 상태', 'Trail 상태·이벤트 선택은 현재 수집하지 않습니다. 추가 증빙을 확인하세요.'),
    ('OPS-002', 'OPS', 'CloudWatch', '경보와 운영 알림', '경보 설정·알림 전달은 현재 수집하지 않습니다. 수동 확인하세요.'),
    ('COST-002', 'COST', 'CloudWatchLogs', '로그 보존 기간', '로그 그룹 보존 기간은 현재 수집하지 않습니다. 보존 목적과 비용을 확인하세요.'),
    ('REL-005', 'REL', 'S3', 'S3 버전 관리', 'S3 버전 관리는 현재 수집하지 않습니다. 복구 요구와 함께 확인하세요.'),
    ('SEC-008', 'SEC', 'S3', 'S3 공개 정책 상태', '버킷 공개 정책 상태는 현재 수집하지 않습니다. 공개 차단 설정만으로 대신 판정하지 않습니다.'),
]
MANUAL = {
    'OPS': ('운영 절차·책임', 'SLO, 소유자, Runbook, 배포·롤백·장애 대응 증빙을 확인하세요.'),
    'SEC': ('권한·데이터 보호', 'IAM 최소 권한, MFA, 데이터 분류, KMS, 계정/조직 차단, S3 ACL·Access Point를 확인하세요.'),
    'REL': ('복원·장애 대응', 'RTO/RPO, 복원 시험, Aurora 토폴로지, 네트워크 의존성과 장애 훈련을 확인하세요.'),
    'PERF': ('성능 측정', '부하·지연·CPU·메모리·IO 사용률과 적정 용량을 확인하세요. 이 버전은 메트릭을 조회하지 않습니다.'),
    'COST': ('비용 할당·구매', '소유자 태그, 예산·청구서, Savings Plans·RI, 라이선스와 보존 목적을 확인하세요.'),
    'SUS': ('수요·수명주기', '수요 일정, 사용률, 데이터 수명주기와 서비스 선택을 확인하세요. 탄소량을 계산하지 않습니다.'),
}


def source(pillar):
    return f'https://docs.aws.amazon.com/wellarchitected/latest/{SLUGS[pillar]}-pillar/welcome.html'


def matching_coverage(report, row):
    result = [c for c in report.get('coverage', []) if c.get('service') == row.get('service')
              and c.get('account') == row.get('account') and c.get('profile') == row.get('profile')
              and c.get('region') in (row.get('region'), 'global')]
    if row.get('service') == 'S3':
        # Bucket-specific errors must never be hidden by a successful ListBuckets.
        result = [c for c in result if c.get('operation') == 'bucket_detail:' + str(row.get('id', ''))]
    return result


def entry(rule, pillar, service, title, severity, status, row, evidence, recommendation):
    return dict(rule=rule, pillar=pillar, pillar_name=PILLARS[pillar], service=service, title=title,
                severity=severity, status=status, profile=row.get('profile', ''), account=row.get('account', ''),
                region=row.get('region', 'scope'), id=row.get('id', 'scope'), evidence=evidence,
                recommendation=recommendation, source=source(pillar))


def evaluate(report):
    """Return an additive WAR snapshot without modifying any existing table."""
    resources, coverage = report.get('resources', []), report.get('coverage', [])
    rows = []
    for spec in RULES:
        rule, pillar, service, title, severity, fields, predicate, recommendation, existing_rule = spec
        relevant = [r for r in resources if r.get('service') == service]
        for r in relevant:
            data = r.get('details')
            result = predicate(data) if isinstance(data, dict) else None
            status = result if isinstance(result, str) else 'PASS' if result is True else 'FAIL' if result is False else 'UNKNOWN'
            queries = matching_coverage(report, r)
            usable = any(c.get('status') in ('OK', 'PARTIAL') for c in queries)
            incomplete = not queries or any(c.get('status') != 'OK' for c in queries)
            if not usable or (incomplete and status in ('PASS', 'NOT_APPLICABLE')):
                status = 'UNKNOWN'
            # Link legacy flags without trusting them as substitutes for missing evidence.
            basic = [f for f in report.get('findings', []) if existing_rule and f.get('rule') == existing_rule
                     and all(f.get(k) == r.get(k) for k in ('profile','account','region','service','id'))]
            conflict = bool(basic) and status == 'PASS'
            if conflict:
                status = 'UNKNOWN'
            evidence = dict(collected_at=report.get('finished_at', report.get('started_at', '')),
                values={field:evidence_value(data, field) for field in fields} if isinstance(data, dict) else {},
                coverage=[{k:c.get(k) for k in ('operation','status','error','count')} for c in queries],
                reason='기존 점검 후보와 관측값이 일치하지 않습니다.' if conflict else '필드 또는 수집 증빙이 부족합니다.' if status == 'UNKNOWN' else '',
                existing_rule=existing_rule or None)
            rows.append(entry(rule,pillar,service,title,severity,status,r,evidence,recommendation))

        # Explicitly account for successful empty and absent/failed regional inventories.
        expected = {(r.get('profile',''), r.get('account',''), r.get('region','scope')) for r in relevant}
        expected.update((c.get('profile',''), c.get('account',''), c.get('region','scope'))
                        for c in coverage if c.get('service') == service)
        identities = {(c.get('profile',''), c.get('account','')) for c in coverage if c.get('account')}
        identities.update((r.get('profile',''), r.get('account','')) for r in resources if r.get('account'))
        requested = report.get('requested_regions', [])
        regions = ['global'] if service in ('IAM','S3') else [r for r in requested if r != 'all']
        expected.update((p,a,region) for p,a in identities for region in regions)
        if not expected:
            expected.add(('', '', 'scope'))
        for profile, account, region in sorted(expected):
            # S3 inventory is global while bucket rows carry actual locations.
            has_rows = any(r.get('profile','') == profile and r.get('account','') == account
                           and (r.get('region','scope') == region or (service == 'S3' and region == 'global')) for r in relevant)
            if has_rows:
                continue
            queries = [c for c in coverage if c.get('service') == service and c.get('profile','') == profile
                       and c.get('account','') == account and c.get('region','scope') == region]
            complete_empty = bool(queries) and all(c.get('status') == 'OK' and c.get('count') == 0 for c in queries)
            status = 'NOT_APPLICABLE' if complete_empty else 'UNKNOWN'
            scope = dict(profile=profile, account=account, region=region, id='scope')
            rows.append(entry(rule,pillar,service,title,severity,status,scope,
                {'reason':'성공한 빈 목록' if complete_empty else '미수집·실패·누락된 인벤토리',
                 'coverage':[{k:c.get(k) for k in ('operation','status','error','count')} for c in queries]},recommendation))

    for c in coverage:
        if c.get('status') != 'OK':
            rows.append(entry('DATA-001','OPS',c.get('service',''),'수집 범위·오류 확인','HIGH','UNKNOWN',c,
                {k:c.get(k) for k in ('operation','status','count','error')},
                '권한·선택 범위와 오류를 확인하세요. 부분 수집에서 확보한 리소스만으로 전체 정상 판정하지 않습니다.'))
    for rule,pillar,service,title,reason in UNAVAILABLE:
        rows.append(entry(rule,pillar,service,title,'INFO','UNKNOWN',{}, {'reason':reason},reason))
    for pillar,(title,reason) in MANUAL.items():
        rows.append(entry(pillar+'-MANUAL',pillar,'Workload',title,'INFO','MANUAL',{}, {'reason':'워크로드 인터뷰 및 추가 증빙 필요'},reason))
    return dict(schema_version=1, ruleset_version=RULESET, evaluated_at=datetime.now(timezone.utc).isoformat(),
                engine='resource-checker-offline', counts=dict(Counter(r['status'] for r in rows)), findings=rows,
                limitations=['AWS 공식 WAR/HRI 판정이나 전체 적합성 점수가 아닌 사전 점검입니다.',
                    '기존 수집 데이터만 평가합니다. AWS API 호출과 권한을 추가하지 않습니다.',
                    'PASS는 해당 관측 조건만 만족합니다. UNKNOWN·MANUAL은 후속 확인이 필요합니다.',
                    '7일 백업, gp2, 상세 모니터링 등은 업무 맥락과 비용을 확인할 검토 기준입니다.',
                    '이 버전은 예외 승인·수동 답변 저장을 제공하지 않습니다.'])


def main():
    parser = argparse.ArgumentParser(description='기존 report.json을 AWS 호출 없이 WAR 평가')
    parser.add_argument('input', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding='utf-8-sig'))
    if not isinstance(report,dict) or not all(isinstance(report.get(k),list) for k in ('resources','findings','coverage')):
        parser.error('Resource Checker report.json이 필요합니다.')
    if args.input.resolve() == args.out.resolve():
        parser.error('입력과 다른 출력 경로를 지정하세요.')
    report['war'] = evaluate(report)
    args.out.write_text(json.dumps(report,ensure_ascii=False,indent=2,default=str),encoding='utf-8')


if __name__ == '__main__':
    main()
