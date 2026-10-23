# AWS Resource Checker — CloudShell

https://unihit.github.io/aws-resource-checker-web/

1. AWS 콘솔 로그인 후 CloudShell을 새 탭에서 엽니다.
2. 웹페이지에서 명령어를 복사해 실행합니다. 기본값은 실행 중인 CloudShell의 리전이며, 리전을 입력할 필요가 없습니다.
3. 표시된 계정 확인 후 Enter. 완료된 ZIP을 Actions → Download file로 내려받습니다.
4. report.html을 열거나 웹페이지에서 report.json을 선택합니다.

현재 콘솔 권한을 사용합니다. 별도 Access Key·OIDC·Role 생성은 필요하지 않지만 CloudShell 사용 및 해당 서비스 조회 권한이 필요합니다. 권한을 자동으로 부여하지 않습니다.

리전은 실행 시 `AWS_REGION`을 우선 사용하고, 없으면 `AWS_DEFAULT_REGION`을 사용합니다. 실행 전에 감지한 리전과 계정을 표시합니다. 환경 변수를 직접 변경했다면 그 값이 사용되므로 표시 내용을 확인하세요. 감지에 실패하거나 값이 잘못되면 임의의 리전으로 조회하지 않고 중단합니다. 웹페이지의 CloudShell 링크도 서울 리전을 강제하지 않습니다.

다른 리전은 **다른 리전 지정 (선택)**을 펼쳐 입력하세요. 여러 리전은 쉼표로 최대 5개, 활성 리전 전체는 `all`을 입력합니다. 직접 지정한 리전이 자동 감지보다 우선합니다. IAM·S3 등 기존 계정 수준 수집 범위는 바뀌지 않습니다.

공개 수집 코드만 내려받고 SHA256 검증 후 실행합니다. 임시 디렉터리의 가상환경에 boto3/XlsxWriter를 설치합니다. 결과는 CloudShell 홈의 aws-resource-checker-reports 아래 저장됩니다. 계정·리소스 정보가 있는 결과 파일을 공개 저장소에 올리지 마세요.

웹페이지는 AWS나 GitHub API를 호출하지 않으며 선택한 보고서는 브라우저 메모리에서만 처리합니다. 자동 분석·외부 폰트·외부 JS 의존성·영구 저장 기능이 없습니다. 데모는 가상 데이터입니다.

collector/에는 일반 조회 수집기, CloudShell 실행기, 오프라인 WAR 규칙 엔진이 포함됩니다. 비공개 저장소 이력, 고객 정보, 실제 결과, 인증 정보는 포함하지 않습니다. 기존 GitHub Actions 방식은 비공개 저장소에서 유지됩니다.

## WAR 사전 진단 (1단계)

현재 CloudShell 인증·수집 범위·서비스별 Excel을 유지하고, 기존 수집 증빙만 사용하는 WAR 평가를 추가했습니다. AWS API와 조회 권한은 추가하지 않습니다. 새 실행에서 생성한 report.json을 열고 **보고서 보기 → WAR 진단** 탭을 선택하세요. Pillar·상태·검색을 함께 사용할 수 있습니다.

- 기존 `resources`, `findings`, `coverage`, 수집 상태는 그대로 유지합니다. 새 `war` 항목에 schema_version=1, 규칙 버전, 평가 시각, 상태별 건수와 상세 결과가 추가됩니다.
- HTML에는 WAR 상세 결과가 추가됩니다. Excel에는 기존 서비스 시트·차트·내부 링크 뒤에 **WAR Summary / WAR Findings / WAR Manual**을 추가합니다. WAR Manual은 UNKNOWN과 MANUAL의 후속 확인 목록입니다.
- 15개 리소스 규칙과 수집 오류 항목, 미수집 증빙 안내 5종, 6 Pillar 인터뷰 항목을 제공합니다. PASS는 관측 조건 충족, FAIL은 개선 검토 후보, UNKNOWN은 필드·수집 증빙 부족, MANUAL은 인터뷰 필요, NOT_APPLICABLE은 확인된 대상 없음입니다. 공식 WAR/HRI 판정이나 준수 점수를 산출하지 않습니다.
- 기존 기본 점검 후보는 변경하지 않습니다. WAR 증빙에서 관련 기존 규칙을 연결하며, 기존 후보와 관측값이 충돌하면 PASS 대신 UNKNOWN입니다.
- CloudTrail 상태, CloudWatch 경보, 로그 보존, S3 버전 관리와 공개 정책 상태는 추가 수집하지 않으므로 UNKNOWN입니다. Aurora 가용성·복원 테스트·권한 정책과 비용·사용률은 수동 검토합니다.
- 권한 오류·부분 수집·누락 필드는 PASS가 아닙니다. 부분 수집에서 확인된 개별 FAIL은 보존하고 별도 UNKNOWN 수집 행을 남깁니다. 성공한 빈 목록만 NOT_APPLICABLE로 평가합니다.
- 예외 승인·담당자/기한 입력·수동 답변 저장·고객별 중앙 이력은 이 단계에서 추가하지 않습니다. 보고서는 계속 브라우저 메모리에서만 열고 서버로 전송하거나 영구 저장하지 않습니다.

예전 JSON도 기존 3개 표에서 계속 열립니다. WAR가 없는 예전 파일은 정상으로 판정하지 않고 WAR 미포함 안내를 표시합니다. 새 CloudShell 명령으로 다시 생성하거나, Python을 사용할 수 있는 환경에서 AWS 호출 없이 변환할 수 있습니다.

```text
python collector/war.py old-report.json --out report-with-war.json
```

입력과 다른 출력 파일을 사용하세요. 이 변환은 원본을 덮어쓰지 않고 JSON만 새로 만듭니다. 예전 수집에서 빠진 필드는 UNKNOWN으로 남으며 자동 조회하지 않습니다.

웹 명령은 `checker.py`, `cloudshell.py`, `war.py` 3개 파일을 내려받아 각각 SHA256을 검증합니다. 배포 직후 코드와 안내가 캐시 때문에 맞지 않으면 실행을 중단합니다. 페이지를 새로고침해 새 명령을 복사하세요. WAR 코드를 수정한 뒤에는 아래 명령으로 샘플 결과와 검증값을 함께 갱신해야 합니다.

```text
python tools/sync_web_data.py
```

## 개발 검증

```text
python -m pip install boto3 xlsxwriter openpyxl
python -m unittest discover -s tests -v
npm install --ignore-scripts
npm test
```

Node 테스트의 linkedom은 개발 검증에만 사용합니다. 공개 페이지는 외부 JavaScript 라이브러리를 로드하지 않습니다. Python 테스트에는 AWS 신원·수집·기존 기본 규칙이 바뀌지 않았는지 확인하는 기준 커밋의 AST 지문과, 기존 서비스별 Excel 시트·차트 보존 검증이 포함됩니다. 테스트는 실제 AWS 계정에 연결하지 않습니다.

