# AWS Resource Checker — CloudShell

https://unihit.github.io/aws-resource-checker-web/

1. AWS 콘솔 로그인 후 CloudShell을 새 탭에서 엽니다.
2. 웹페이지에서 리전·범위를 고르고 명령어를 복사해 실행합니다.
3. 표시된 계정 확인 후 Enter. 완료된 ZIP을 Actions → Download file로 내려받습니다.
4. report.html을 열거나 웹페이지에서 report.json을 선택합니다.

현재 콘솔 권한을 사용합니다. 별도 Access Key·OIDC·Role 생성은 필요하지 않지만 CloudShell 사용 및 해당 서비스 조회 권한이 필요합니다. 권한을 자동으로 부여하지 않습니다.

공개 수집 코드만 내려받고 SHA256 검증 후 실행합니다. 임시 디렉터리의 가상환경에 boto3/XlsxWriter를 설치합니다. 결과는 CloudShell 홈의 aws-resource-checker-reports 아래 저장됩니다. 계정·리소스 정보가 있는 결과 파일을 공개 저장소에 올리지 마세요.

웹페이지는 AWS나 GitHub API를 호출하지 않으며 선택한 보고서는 브라우저 메모리에서만 처리합니다. 자동 분석·외부 폰트·외부 JS 의존성·영구 저장 기능이 없습니다. 데모는 가상 데이터입니다.

collector/에는 일반 조회 수집기와 CloudShell 실행기만 포함됩니다. 비공개 저장소 이력, 고객 정보, 실제 결과, 인증 정보는 포함하지 않습니다. 기존 GitHub Actions 방식은 비공개 저장소에서 유지됩니다.
