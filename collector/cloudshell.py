"""Run the reviewed collector using the current AWS console identity."""
import argparse
import os
from pathlib import Path
import re
import sys
import zipfile

# This file is distributed alongside checker.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import checker

CORE = ['EC2', 'EBS', 'EIP', 'SecurityGroup', 'RDS', 'Aurora']


def parse_regions(value):
    values = list(dict.fromkeys(re.split(r'[\s,]+', value.strip())))
    if values in (['all'], ['auto']):
        return values
    if not 1 <= len(values) <= 5 or any(not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+', v) for v in values):
        raise ValueError('리전은 최대 5개 또는 all 단독으로 입력하세요.')
    return values


def current_region(environ=None):
    environ = os.environ if environ is None else environ
    region = (environ.get('AWS_REGION') or environ.get('AWS_DEFAULT_REGION') or '').strip()
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+', region):
        raise ValueError('CloudShell 현재 리전을 감지하지 못했습니다. CloudShell 리전을 확인하거나 --regions ap-northeast-2처럼 직접 지정하세요.')
    return region


def resolve_regions(regions, environ=None):
    return [current_region(environ)] if regions == ['auto'] else list(regions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--regions', default='auto', type=parse_regions,
                        help='기본 auto: CloudShell 현재 리전. 리전 목록 또는 all로 직접 지정 가능')
    parser.add_argument('--scope', choices=['core', 'full'], default='core')
    parser.add_argument('--demo', action='store_true')
    parser.add_argument('--war', action='store_true', help='WAR 사전 진단 포함 (기본 제외)')
    parser.add_argument('--out', default=str(Path.home() / 'aws-resource-checker-reports'))
    args = parser.parse_args()
    if args.demo:
        report = checker.demo()
    else:
        try:
            regions = resolve_regions(args.regions)
            session_region = current_region() if regions == ['all'] else regions[0]
        except ValueError as exc:
            parser.error(str(exc))
        import boto3
        # Scope changes to this process. Keep CloudShell's credential-forwarding
        # variables intact; do not read legacy keys, profiles or web identity.
        for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                     'AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN', 'AWS_PROFILE',
                     'AWS_DEFAULT_PROFILE', 'AWS_ROLE_ARN',
                     'AWS_WEB_IDENTITY_TOKEN_FILE'):
            os.environ.pop(name, None)
        os.environ['AWS_SHARED_CREDENTIALS_FILE'] = os.devnull
        os.environ['AWS_CONFIG_FILE'] = os.devnull
        session = boto3.Session(region_name=session_region)
        identity = session.client('sts').get_caller_identity()
        print('\n조회 대상 AWS 계정:', identity['Account'])
        print('현재 로그인 역할:', identity['Arn'])
        print('조회 리전:', ', '.join(regions),
              '(CloudShell 현재 리전 자동 감지)' if args.regions == ['auto'] else '(직접 지정)',
              '/ 범위:', args.scope)
        print('WAR 사전 진단:', '포함' if args.war else '제외')
        if input('계정이 맞으면 Enter, 중단하려면 n 입력: ').strip():
            print('조회하지 않고 종료했습니다.')
            return 0
        report = checker.scan(['cloudshell'], regions,
                              CORE if args.scope == 'core' else None,
                              session_factory=lambda **kwargs: session, use_env=True)
    folder = checker.export_report(report, args.out, include_war=args.war)
    archive = folder.with_suffix('.zip')
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as output:
        for name in ('report.html', 'report.json', 'report.xlsx'):
            path = folder / name
            if path.exists():
                output.write(path, name)
    print('\n결과:', report['status'])
    print('CloudShell의 Actions → Download file에 아래 경로를 붙여넣으세요:')
    print(archive)
    print('ZIP 압축을 풀고 report.html을 열거나, 웹페이지에서 report.json을 선택하세요.')
    print('보고서에는 계정·리소스 정보가 있으므로 내부 자료로 보관하세요.')
    return 0 if args.demo or report['status'] == 'COMPLETE' else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
        print('실행 실패:', code, '— 콘솔 로그인과 CloudShell·조회 권한을 확인하세요.', file=sys.stderr)
        raise SystemExit(1)
