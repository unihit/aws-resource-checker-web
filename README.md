# AWS Resource Checker — Browser Guide

AWS IAM 연결 안내, 계정별 정책 JSON 생성, 로컬 report.json 뷰어입니다.

- AWS Access Key, Secret Key 또는 GitHub 토큰을 입력·저장하지 않습니다.
- 입력한 계정 ID와 선택한 보고서는 브라우저 메모리에서만 처리합니다.
- 페이지에서 AWS나 GitHub API를 직접 호출하지 않습니다. 실제 조회는 사용 권한이 있는 비공개 GitHub Actions 저장소에서 실행합니다.
- 샘플은 계정 `000000000000`의 가상 데이터입니다.
- HTML의 안내에 따라 IAM 공급자·정책·역할을 생성할 수 있습니다.
- 화면의 설정 완료 체크는 자가 확인이며 실제 인증 결과는 GitHub Actions에서 확인합니다.

이 저장소는 공개 화면 파일만 포함합니다. 실제 리소스 보고서, AWS 수집기, 인증 자격 증명은 포함하지 않습니다.

공개 전 검토 내역은 [SECURITY-REVIEW.md](SECURITY-REVIEW.md)를 참고하세요.
