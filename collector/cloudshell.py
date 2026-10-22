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
    if values == ['all']:
        return values
    if not 1 <= len(values) <= 5 or any(not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+', v) for v in values):
        raise ValueError('리전은 최대 5개 또는 all 단독으로 입력하세요.')
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--regions', default='ap-northeast-2', type=parse_regions)
    parser.add_argument('--scope', choices=['core', 'full'], default='core')
    parser.add_argument('--demo', action='store_true')
    parser.add_argument('--out', default=str(Path.home() / 'aws-resource-checker-reports'))
    args = parser.parse_args()
    if args.demo:
        report = checker.demo()
    else:
        import boto3
        # Ignore named-profile selectors; use credentials forwarded by CloudShell.
        os.environ.pop('AWS_PROFILE', None)
        os.environ.pop('AWS_DEFAULT_PROFILE', None)
        session = boto3.Session()
        identity = session.client('sts').get_caller_identity()
        print('\n조회 대상 AWS 계정:', identity['Account'])
        print('현재 로그인 역할:', identity['Arn'])
        print('조회 리전:', ', '.join(args.regions), '/ 범위:', args.scope)
        if input('계정이 맞으면 Enter, 중단하려면 n 입력: ').strip():
            print('조회하지 않고 종료했습니다.')
            return 0
        report = checker.scan(['cloudshell'], args.regions,
                              CORE if args.scope == 'core' else None,
                              session_factory=lambda **kwargs: session, use_env=True)
    folder = checker.export_report(report, args.out)
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
