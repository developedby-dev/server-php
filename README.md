# 데브 서버 도우미: PHP

판매자 서버에서 쓰는 두 기능만 담은 작은 패키지입니다. Laravel, Symfony, WordPress 같은 PHP 서버에서 웹훅 서명을 검증하고, 토큰(access_token,
licenseToken)을 검증합니다.

로그인이나 세션 같은 데스크톱 앱용 기능은 들어 있지 않습니다. 의존성은 PHP 기본 확장뿐입니다.

| 지원 | 버전 |
|---|---|
| 동작 명세 | 1.1.1 (12절 서버 도우미) |
| PHP | 8.2 이상과 `ext-sodium`(대부분의 배포판에 기본으로 들어 있습니다). `ext-sodium`이 없으면 PHP 8.4 이상에서 `ext-openssl`을 씁니다. |

패키지 이름은 `bydev/server`입니다. 지금 Packagist에 있는 0.x 판은 이름을 먼저 등록하려고 낸 미리보기입니다. 1.0.0은 서비스 오픈과 함께 내며, 그 전에는
호환되지 않는 변경이 있을 수 있습니다. 판매하는 서비스에는 1.0.0 이상을 써 주세요.

## 빠른 시작

```php
use Bydev\BydevException;
use Bydev\Codes;
use Bydev\ServerVerifier;
use Bydev\Webhook;

// 웹훅: 받은 본문 그대로 검증하세요. json_decode했다가 다시 만든 문자열로는 서명이 맞지 않습니다. 시크릿을 교체하는 중이면 둘 다 넘기세요
try {
    $event = Webhook::verify([getenv('BYDEV_WEBHOOK_SECRET')], getallheaders(), file_get_contents('php://input'));
} catch (BydevException $e) {
    http_response_code(400); // $e->errorCode === Codes::WEBHOOK_INVALID
    exit;
}
// $event->id로 중복 수신을 걸러 주세요

// 앱이 보낸 access_token을 검증합니다. 요청이 끝난 뒤에도 JWKS를 유지하려면 PSR-16 캐시(APCu, Redis, Laravel, Symfony)를 넘기세요
$verifier = new ServerVerifier('https://api.developedby.dev', 'cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW', cache: $psr16Cache);
$claims = $verifier->verifyAccessToken($bearerToken); // $claims->sub는 이 판매자 전용 가명 식별자입니다
```

## 사용 조건

- **실패**하면 `BydevException`이 발생합니다. 분기는 `errorCode`로 해 주세요.

  값은 `Codes::*`에 있으며, `WEBHOOK_INVALID`, `TOKEN_INVALID`,
  `GENERATION_REGRESSED`, `NETWORK_ERROR` 등이 있습니다. PHP 예외에 원래 있는 정수 `getCode()`와 겹치지 않도록 이름을 따로 두었습니다.
- **JWKS 캐시**: PHP는 요청마다 메모리가 비워집니다. 그래서 캐시가 없으면 요청마다 발견 문서(`/.well-known/openid-configuration`)와 JWKS를 새로
  받습니다. `get`과 `set`이 있는 PSR-16 형태의 객체를 넘기면, 응답의 `Cache-Control: max-age` 동안 보관합니다.

  처음 보는 `kid`가 오면 마지막으로 받은
  지 1분이 지났을 때만 다시 받습니다.
- **licenseToken**: `verifyLicenseToken($token, $minGeneration)`을 사용해 주세요. 같은 사용자와 기기에서 지금까지 본 가장 큰 세대번호(세션을 새로 얻거나
  인수할 때마다 커지는 번호)를 넘기면, 그보다 작은 세대번호의 토큰은 거부합니다.
- **HTTP**: `ext-curl`이 있으면 curl을, 없으면 PHP 스트림을 씁니다. 리다이렉트는 따라가지 않습니다.

  프록시가 필요하면 `http:` 인자에 같은 모양의
  함수를 전달해 주세요.
- 라이선스는 MIT 또는 Apache-2.0입니다.

## 출처 확인

이 꾸러미는 공개 저장소 `developedby-dev/server-php`의 GitHub Actions가 판 태그에서 짓고 올립니다. 판 태그마다 올린 소스 묶음에는 GitHub 출처 증명이 있습니다. 받은 파일을 `gh attestation verify <파일> --repo developedby-dev/server-php`로 확인할 수 있습니다.

## 개발

| 명령 | 하는 일 |
|---|---|
| `php tests/run.php` | 의존성 없이 시험을 돌립니다. 웹훅 안내서의 예시, sodium과 openssl 두 방식의 토큰 검증, JWKS 캐시 규칙, `php -S`로 띄운 실제 HTTP 통신을 확인합니다. |
| `pnpm sdk:check php` | 같은 시험을 돌립니다. |

`src/Generated.php`는 생성된 파일이며, `pnpm --filter @bydev/sdk-codegen generate`로 다시 만듭니다.
