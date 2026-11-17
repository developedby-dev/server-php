<?php

// 시험 — 의존성 없이 `php tests/run.php`. 실패하면 0이 아닌 코드로 끝난다.

declare(strict_types=1);

require __DIR__ . '/../src/Generated.php';
spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'Bydev\\')) {
        require __DIR__ . '/../src/' . substr($class, 6) . '.php';
    }
});

use Bydev\AccessClaims;
use Bydev\BydevException;
use Bydev\Codes;
use Bydev\Ed25519;
use Bydev\Http;
use Bydev\ServerVerifier;
use Bydev\Webhook;
use Bydev\WebhookVerification;

$failures = 0;
$count = 0;

function check(bool $ok, string $what): void
{
    global $failures, $count;
    $count++;
    if (!$ok) {
        $failures++;
        fwrite(STDERR, "✗ {$what}\n");
    }
}

function rejects(string $code, callable $call, string $what): void
{
    try {
        $call();
        check(false, "{$what} — 던지지 않았다");
    } catch (BydevException $e) {
        check($e->errorCode === $code, "{$what} — {$e->errorCode} ≠ {$code}");
    }
}

function b64url(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

// ── 웹훅 — 안내서 11장의 서명 예시(TS · Go · .NET · Kotlin · Python 시험과 같은 값) ──

$secret = 'whsec_/MU12AiKByBoT7xt+p81N/uKdp/WxQRb';
$id = 'evt_01J9MC4D6E8F0G2H4J6K8M0N2P';
$sent = 1791295205;
$body = '{"id":"evt_01J9MC4D6E8F0G2H4J6K8M0N2P","type":"build.review_completed","occurredAt":"2026-10-06T14:00:00Z","mode":"LIVE","simulated":false,"data":{"build":{"id":"build_01J9M4D6F8H0J2K4M6N8P0R2S4","productId":"prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD","version":"1.4.2","reviewedAt":"2026-10-06T13:58:00Z","result":"APPROVED"}}}';
$signature = 'v1,vmsiq2HY4gik/WNJjXJzuESzXAjJgr8Vi13SKwwhgEo=';
$headers = static fn (string $sig): array => ['Webhook-Id' => $id, 'Webhook-Timestamp' => (string) $sent, 'Webhook-Signature' => $sig];

check(Webhook::verify([$secret], $headers($signature), $body, $sent + 10) == new WebhookVerification($id, $sent), '웹훅 — 안내서 예시');
// PSR-7 getHeaders() 모양(값이 배열)
check(Webhook::verify([$secret], ['webhook-id' => [$id], 'webhook-timestamp' => [(string) $sent], 'webhook-signature' => [$signature]], $body, $sent)->id === $id, '웹훅 — 배열 헤더');
// 서명 여러 개 · 시크릿 여러 개 중 하나라도 맞으면
Webhook::verify([$secret], $headers("v1,AAAA {$signature}"), $body, $sent);
Webhook::verify(['whsec_AAAAAAAAAAAAAAAAAAAAAAAA', $secret], $headers($signature), $body, $sent);
rejects(Codes::WEBHOOK_INVALID, fn () => Webhook::verify([$secret], $headers($signature), $body . ' ', $sent), '웹훅 — 본문 변조');
rejects(Codes::WEBHOOK_INVALID, fn () => Webhook::verify([$secret], $headers($signature), $body, $sent + 301), '웹훅 — 늦은 재전송');
rejects(Codes::WEBHOOK_INVALID, fn () => Webhook::verify([$secret], $headers($signature), $body, $sent - 301), '웹훅 — 미래 시각');
rejects(Codes::WEBHOOK_INVALID, fn () => Webhook::verify([$secret], ['webhook-id' => $id], $body, $sent), '웹훅 — 헤더 없음');
rejects(Codes::WEBHOOK_INVALID, fn () => Webhook::verify([$secret], $headers('v2,' . substr($signature, 3)), $body, $sent), '웹훅 — 다른 서명 판');
rejects(Codes::CONFIGURATION, fn () => Webhook::verify(['/MU12AiKByBoT7xt+p81N/uKdp/WxQRb'], $headers($signature), $body, $sent), '웹훅 — 접두사 없는 시크릿');

// ── 토큰 검증 — 가짜 HTTP · 가상 시계 ──

const BASE = 'https://api.example.test';
const CLIENT = 'cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW';
$keyPair = sodium_crypto_sign_keypair();
$secretKey = sodium_crypto_sign_secretkey($keyPair);
$publicKey = sodium_crypto_sign_publickey($keyPair);
$now = 1791295205;

function mint(string $secretKey, string $kid, string $typ, array $claims, string $alg = 'EdDSA'): string
{
    $input = b64url(json_encode(['alg' => $alg, 'typ' => $typ, 'kid' => $kid])) . '.' . b64url(json_encode($claims));
    return $input . '.' . b64url(sodium_crypto_sign_detached($input, $secretKey));
}

$access = static fn (array $over = []): array => [
    'iss' => BASE, 'sub' => 'psub_01J9M5X3W1V9T7S5R3Q1P9N7M5', 'aud' => CLIENT, 'client_id' => CLIENT,
    'scope' => 'entitlement.read', 'iat' => $now, 'exp' => $now + 3600, 'jti' => 'at_php0001', ...$over,
];
$license = static fn (int $generation, array $over = []): array => [
    'iss' => BASE, 'sub' => 'psub_01J9M5X3W1V9T7S5R3Q1P9N7M5', 'aud' => CLIENT, 'product_id' => 'prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD',
    'device_id' => 'dev_01J9M0Z8Y7X6W5V4T3S2R1Q0P9', 'sid' => 'sess_01J9M2P8Q7R6S5T4V3W2X1Y0Z9', 'generation' => $generation,
    'iat' => $now, 'exp' => $now + 600, ...$over,
];

final class FakeApi
{
    public array $hits = [];
    public array $keys;
    public string $issuer = BASE;

    public function __construct(string $publicKey)
    {
        $this->keys = ['srv-k1' => $publicKey];
    }

    public function __invoke(string $url): array
    {
        $path = parse_url($url, PHP_URL_PATH);
        $this->hits[] = $path;
        if ($path === '/.well-known/openid-configuration') {
            return [200, [], json_encode(['issuer' => $this->issuer, 'jwks_uri' => BASE . '/.well-known/jwks.json'])];
        }
        $jwks = [];
        foreach ($this->keys as $kid => $raw) {
            $jwks[] = ['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => $kid, 'x' => b64url($raw)];
        }
        $jwks[] = ['kty' => 'RSA', 'kid' => 'rsa-k1', 'n' => 'x', 'e' => 'AQAB']; // 다른 키는 버린다
        return [200, ['cache-control' => 'public, max-age=300'], json_encode(['keys' => $jwks])];
    }
}

/** PSR-16 모양의 메모리 캐시 */
final class ArrayCache
{
    public array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->items[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->items[$key] = $value;
        return true;
    }
}

foreach (['sodium', 'openssl'] as $backend) {
    Ed25519::$force = $backend;
    $api = new FakeApi($publicKey);
    $clock = 0;
    $verifier = new ServerVerifier(BASE . '/', CLIENT, $api, static function () use (&$clock, $now): int {
        return $now + $clock;
    });
    $claims = $verifier->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access()));
    check($claims == new AccessClaims(BASE, 'psub_01J9M5X3W1V9T7S5R3Q1P9N7M5', CLIENT, CLIENT, 'entitlement.read', $now, $now + 3600, 'at_php0001'), "{$backend} — access_token 클레임");
    rejects(Codes::TOKEN_INVALID, fn () => $verifier->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access(['aud' => 'cli_other_client_00000000']))), "{$backend} — 다른 aud");
    rejects(Codes::TOKEN_INVALID, fn () => $verifier->verifyAccessToken(mint($secretKey, 'srv-k1', 'license+jwt', $access())), "{$backend} — typ");
    rejects(Codes::TOKEN_INVALID, fn () => $verifier->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access(), 'RS256')), "{$backend} — alg");
    rejects(Codes::TOKEN_INVALID, fn () => $verifier->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access(['exp' => $now - 61]))), "{$backend} — 만료(허용 60초 넘음)");
    $verifier->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access(['exp' => $now - 30]))); // 허용 안
    $forged = mint(sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair()), 'srv-k1', 'at+jwt', $access());
    rejects(Codes::TOKEN_INVALID, fn () => $verifier->verifyAccessToken($forged), "{$backend} — 다른 키의 서명");
    rejects(Codes::TOKEN_INVALID, fn () => $verifier->verifyAccessToken('a.b'), "{$backend} — 형식");
    // 모르는 kid — 1분 안에는 다시 받지 않는다
    rejects(Codes::TOKEN_INVALID, fn () => $verifier->verifyAccessToken(mint($secretKey, 'srv-k9', 'at+jwt', $access())), "{$backend} — 모르는 kid");
    check($api->hits === ['/.well-known/jwks.json', '/.well-known/openid-configuration'] || $api->hits === ['/.well-known/openid-configuration', '/.well-known/jwks.json'], "{$backend} — JWKS는 한 번: " . implode(',', $api->hits));
    // 1분 뒤 모르는 kid는 다시 받는다 — 새 키가 실렸다
    $second = sodium_crypto_sign_keypair();
    $api->keys = ['srv-k2' => sodium_crypto_sign_publickey($second)];
    $clock = 61;
    $verifier->verifyAccessToken(mint(sodium_crypto_sign_secretkey($second), 'srv-k2', 'at+jwt', $access()));
    // 통째로 바꿨다 — 빠진 srv-k1은 더는 믿지 않는다(그리고 1분 안이라 다시 받지 않는다)
    rejects(Codes::TOKEN_INVALID, fn () => $verifier->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access())), "{$backend} — 빠진 키");
    // max-age가 지나면 다시 받는다
    $api->keys = ['srv-k1' => $publicKey];
    $before = count($api->hits);
    $clock = 61 + 301;
    $verifier->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access(['exp' => $now + 7200])));
    check(count($api->hits) === $before + 1, "{$backend} — max-age 뒤 다시 받기");
    // licenseToken · 세대번호
    $clock = 0;
    $licenseVerifier = new ServerVerifier(BASE, CLIENT, new FakeApi($publicKey), static fn (): int => $now);
    check($licenseVerifier->verifyLicenseToken(mint($secretKey, 'srv-k1', 'license+jwt', $license(3)), 3)->generation === 3, "{$backend} — licenseToken");
    check($licenseVerifier->verifyLicenseToken(mint($secretKey, 'srv-k1', 'license+jwt', $license(3)))->buildId === null, "{$backend} — build_id 없음");
    check($licenseVerifier->verifyLicenseToken(mint($secretKey, 'srv-k1', 'license+jwt', $license(3, ['build_id' => 'build_01J9M4D6F8H0J2K4M6N8P0R2S4'])))->buildId === 'build_01J9M4D6F8H0J2K4M6N8P0R2S4', "{$backend} — build_id");
    rejects(Codes::GENERATION_REGRESSED, fn () => $licenseVerifier->verifyLicenseToken(mint($secretKey, 'srv-k1', 'license+jwt', $license(2)), 3), "{$backend} — 세대번호 되돌림");
}
Ed25519::$force = null;

// issuer가 baseUrl과 다르면 설정 실수
$wrongIssuer = new FakeApi($publicKey);
$wrongIssuer->issuer = 'https://evil.example.test';
rejects(Codes::CONFIGURATION, fn () => (new ServerVerifier(BASE, CLIENT, $wrongIssuer, static fn (): int => $now))->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access())), 'issuer 불일치');

// 캐시를 주면 다음 요청(새 인스턴스)은 받지 않는다
$cache = new ArrayCache();
$api = new FakeApi($publicKey);
(new ServerVerifier(BASE, CLIENT, $api, static fn (): int => $now, $cache))->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access()));
$hits = count($api->hits);
(new ServerVerifier(BASE, CLIENT, $api, static fn (): int => $now + 10, $cache))->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access()));
check($hits === 2 && count($api->hits) === 2, '캐시 — 다음 인스턴스는 받지 않는다');
(new ServerVerifier(BASE, CLIENT, $api, static fn (): int => $now + 400, $cache))->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access()));
check(count($api->hits) === 3, '캐시 — max-age가 지나면 JWKS만 다시 받는다');

// 서버 에러 · 연결 실패
rejects(Codes::INTERNAL_ERROR, fn () => (new ServerVerifier(BASE, CLIENT, static fn (string $url): array => [503, [], 'down'], static fn (): int => $now))->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access())), '503');
rejects(Codes::NETWORK_ERROR, fn () => (new ServerVerifier(BASE, CLIENT, static function (string $url): array {
    throw new \RuntimeException('연결 끊김');
}, static fn (): int => $now))->verifyAccessToken(mint($secretKey, 'srv-k1', 'at+jwt', $access())), '연결 실패');

// ── 실제 HTTP — php -S 시험 서버, 기본 전송(curl · 스트림) ──

$port = 0;
$probe = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($probe, false))[1];
fclose($probe);
$env = array_merge(getenv(), ['BYDEV_TEST_X' => b64url($publicKey)]);
$server = proc_open([PHP_BINARY, '-S', "127.0.0.1:{$port}", __DIR__ . '/fixtures/router.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, null, $env);
$base = "http://127.0.0.1:{$port}";
for ($i = 0; $i < 50 && @fsockopen('127.0.0.1', $port) === false; $i++) {
    usleep(100_000);
}
try {
    foreach (['curl', 'stream'] as $transport) {
        Http::$force = $transport;
        $realNow = time();
        $token = mint($secretKey, 'srv-k1', 'at+jwt', $access(['iss' => $base, 'iat' => $realNow, 'exp' => $realNow + 600]));
        check((new ServerVerifier($base, CLIENT))->verifyAccessToken($token)->sub === 'psub_01J9M5X3W1V9T7S5R3Q1P9N7M5', "{$transport} — 실제 HTTP로 발견 문서 · JWKS");
        [$status, $headers] = Http::get("{$base}/redirect");
        check($status === 302 && $headers['location'] === '/.well-known/jwks.json', "{$transport} — 리다이렉트를 따라가지 않는다 · 헤더는 소문자");
        [$status] = Http::get("{$base}/nope");
        check($status === 404, "{$transport} — 2xx가 아닌 응답도 응답");
    }
    Http::$force = null;
    rejects(Codes::NETWORK_ERROR, fn () => Http::get('http://127.0.0.1:1/'), '연결하지 못하면 NETWORK_ERROR');
} finally {
    proc_terminate($server);
    proc_close($server);
}

echo $failures === 0 ? "시험 {$count}개 통과\n" : "시험 {$count}개 중 {$failures}개 실패\n";
exit($failures === 0 ? 0 : 1);
