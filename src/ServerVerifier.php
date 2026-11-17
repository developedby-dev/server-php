<?php

declare(strict_types=1);

namespace Bydev;

/**
 * 판매자 서버의 토큰 검증 (명세 9 · 12절 · 안내서 09장) — 발견 문서와 JWKS를 받아 access_token(`at+jwt`) · licenseToken(`license+jwt`)의
 * 서명 · `iss` · `aud` · `exp`를 확인한다.
 *
 * PHP는 요청마다 메모리가 비므로, 받은 발견 문서 · JWKS를 요청 너머로 두려면 PSR-16 모양의 캐시(`get($key, $default)` · `set($key, $value, $ttl)` —
 * APCu · Redis · Symfony · Laravel 캐시)를 준다. JWKS는 응답의 `Cache-Control: max-age`까지만 두고(명세 9.1), 모르는 `kid`는 마지막으로 받은 지 1분이
 * 지났을 때만 다시 받는다. 캐시가 없으면 인스턴스 하나 동안만 둔다.
 */
final class ServerVerifier
{
    private const CACHE_PREFIX = 'bydev.server.';

    /** @var (callable(string): array{0: int, 1: array<string, string>, 2: string}) */
    private $http;
    /** @var (callable(): (int|float)) */
    private $clock;
    /** @var array{issuer: string, jwks_uri: string}|null */
    private ?array $discovery = null;
    /** @var array{keys: array<string, string>, fetchedAt: float, expiresAt: float}|null */
    private ?array $keySet = null;
    private readonly string $baseUrl;

    /**
     * @param (callable(string): array{0: int, 1: array<string, string>, 2: string})|null $http GET — 상태 · 소문자 헤더 · 본문 (기본 `Http::get`)
     * @param (callable(): (int|float))|null $clock 지금(Unix 초) — 시험에서 준다
     * @param object|null $cache PSR-16 모양의 캐시(선택)
     */
    public function __construct(
        string $baseUrl,
        private readonly string $clientId,
        ?callable $http = null,
        ?callable $clock = null,
        private readonly ?object $cache = null,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->http = $http ?? [Http::class, 'get'];
        $this->clock = $clock ?? static fn (): float => microtime(true);
        if (!function_exists('sodium_crypto_sign_verify_detached') && !Ed25519::opensslAvailable()) {
            throw new BydevException(Codes::CONFIGURATION, 'Ed25519 서명을 확인할 수 없다 — ext-sodium 또는 ext-openssl(PHP 8.4 이상)이 필요하다');
        }
    }

    /** access_token(at+jwt)을 검증한다 — 앱이 판매자 서버에 보낸 토큰으로 사용자를 알아볼 때. */
    public function verifyAccessToken(string $token): AccessClaims
    {
        return AccessClaims::read($this->verifySigned($token, 'at+jwt'));
    }

    /**
     * licenseToken(license+jwt)을 검증한다. `$minGeneration` — 같은 sub · device_id에서 판매자 서버가 이미 본 가장 큰 세대번호(0이면 보지 않는다).
     * 그보다 작으면 GENERATION_REGRESSED.
     */
    public function verifyLicenseToken(string $token, int $minGeneration = 0): LicenseClaims
    {
        $claims = LicenseClaims::read($this->verifySigned($token, 'license+jwt'));
        if ($minGeneration > 0 && $claims->generation < $minGeneration) {
            throw new BydevException(Codes::GENERATION_REGRESSED, "세대번호 {$claims->generation} < 이미 본 {$minGeneration}");
        }
        return $claims;
    }

    /** @return array<string, mixed> 9절 1 ~ 4를 통과한 페이로드 */
    private function verifySigned(string $token, string $typ): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw self::invalid('JWT 형식이 아니다');
        }
        $header = self::json(self::base64url($parts[0]));
        $payload = self::json(self::base64url($parts[1]));
        $signature = self::base64url($parts[2]);
        if (!is_array($header) || !is_array($payload) || $signature === null) {
            throw self::invalid('JWT를 읽지 못했다');
        }
        if (($header['alg'] ?? null) !== 'EdDSA') {
            throw self::invalid('alg가 EdDSA가 아니다');
        }
        if (($header['typ'] ?? null) !== $typ) {
            throw self::invalid("typ가 {$typ}가 아니다");
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw self::invalid('kid가 없다');
        }
        if (!Ed25519::verify($signature, $parts[0] . '.' . $parts[1], $this->keyFor($kid))) {
            throw self::invalid('서명이 맞지 않는다');
        }
        if (($payload['iss'] ?? null) !== $this->discovery()['issuer']) {
            throw self::invalid('iss가 다르다');
        }
        if (($payload['aud'] ?? null) !== $this->clientId) {
            throw self::invalid('aud가 이 client_id가 아니다');
        }
        $exp = $payload['exp'] ?? null;
        if (!is_int($exp) || $exp <= ($this->clock)() - Rules::TOKEN_CLOCK_LEEWAY_SEC) {
            throw self::invalid('만료된 토큰');
        }
        return $payload;
    }

    /** 9.1절 — 지난 캐시는 쓰지 않는다 · 모르는 kid는 1분에 한 번만 다시 받는다 */
    private function keyFor(string $kid): string
    {
        $now = ($this->clock)();
        $set = $this->keySet ?? $this->cached('jwks');
        if ($set === null || $now >= $set['expiresAt']) {
            $set = $this->fetchKeys();
        }
        if (isset($set['keys'][$kid])) {
            return $set['keys'][$kid];
        }
        if ($now - $set['fetchedAt'] < Rules::JWKS_UNKNOWN_KID_REFETCH_MIN_INTERVAL_SEC) {
            throw self::invalid("모르는 kid {$kid}");
        }
        $fresh = $this->fetchKeys();
        return $fresh['keys'][$kid] ?? throw self::invalid("모르는 kid {$kid}");
    }

    /** @return array{keys: array<string, string>, fetchedAt: float, expiresAt: float} */
    private function fetchKeys(): array
    {
        [$headers, $body] = $this->get($this->discovery()['jwks_uri']);
        $keys = [];
        foreach ((is_array($body['keys'] ?? null) ? $body['keys'] : []) as $jwk) {
            if (!is_array($jwk) || ($jwk['kty'] ?? null) !== 'OKP' || ($jwk['crv'] ?? null) !== 'Ed25519') {
                continue;
            }
            $kid = $jwk['kid'] ?? null;
            $raw = is_string($jwk['x'] ?? null) ? self::base64url($jwk['x']) : null;
            if (is_string($kid) && $kid !== '' && $raw !== null && strlen($raw) === 32) {
                $keys[$kid] = $raw;
            }
        }
        $maxAge = Rules::JWKS_DEFAULT_MAX_AGE_SEC;
        if (preg_match('/(?:^|,)\s*max-age=(\d+)/', $headers['cache-control'] ?? '', $m) === 1) {
            $maxAge = (int) $m[1];
        }
        $now = ($this->clock)();
        // 통째로 바꾼다 — 빠진 키는 더는 믿지 않는다
        $this->keySet = ['keys' => $keys, 'fetchedAt' => (float) $now, 'expiresAt' => (float) $now + $maxAge];
        $this->store('jwks', $this->keySet, $maxAge + Rules::JWKS_UNKNOWN_KID_REFETCH_MIN_INTERVAL_SEC);
        return $this->keySet;
    }

    /** @return array{issuer: string, jwks_uri: string} 처음 한 번 받아 둔다. issuer가 baseUrl과 다르면 CONFIGURATION (명세 4절) */
    private function discovery(): array
    {
        if ($this->discovery !== null) {
            return $this->discovery;
        }
        $cached = $this->cached('discovery');
        if ($cached === null) {
            [, $body] = $this->get($this->baseUrl . '/.well-known/openid-configuration');
            $issuer = $body['issuer'] ?? null;
            $jwks = $body['jwks_uri'] ?? null;
            if (!is_string($issuer) || !is_string($jwks)) {
                throw new BydevException(Codes::PROTOCOL_ERROR, '발견 문서에 issuer · jwks_uri가 없다');
            }
            if (rtrim($issuer, '/') !== $this->baseUrl) {
                throw new BydevException(Codes::CONFIGURATION, "발견 문서의 issuer({$issuer})가 baseUrl({$this->baseUrl})과 다르다");
            }
            $cached = ['issuer' => $issuer, 'jwks_uri' => $jwks];
            $this->store('discovery', $cached, 86400);
        }
        return $this->discovery = $cached;
    }

    /** @return array{0: array<string, string>, 1: array<string, mixed>} 2xx면 헤더 · JSON, 아니면 에러 */
    private function get(string $url): array
    {
        try {
            [$status, $headers, $body] = ($this->http)($url);
        } catch (BydevException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new BydevException(Codes::NETWORK_ERROR, 'API에 연결하지 못했다', null, $e);
        }
        $json = self::json($body);
        if ($status >= 200 && $status < 300) {
            if (!is_array($json)) {
                throw new BydevException(Codes::PROTOCOL_ERROR, '응답 본문이 JSON이 아니다', $status);
            }
            return [$headers, $json];
        }
        if (is_array($json) && is_string($json['code'] ?? null) && is_string($json['message'] ?? null)) {
            throw new BydevException($json['code'], $json['message'], $status);
        }
        $code = $status >= 500 ? Codes::INTERNAL_ERROR : ($status === 429 ? Codes::RATE_LIMITED : Codes::PROTOCOL_ERROR);
        throw new BydevException($code, "HTTP {$status}", $status);
    }

    /** @return array<string, mixed>|null */
    private function cached(string $name): ?array
    {
        if ($this->cache === null) {
            return null;
        }
        $value = $this->cache->get(self::CACHE_PREFIX . $name . '.' . md5($this->baseUrl));
        $decoded = is_string($value) ? self::json($value) : null;
        if (!is_array($decoded)) {
            return null;
        }
        if ($name === 'jwks') {
            $keys = [];
            foreach ((array) ($decoded['keys'] ?? []) as $kid => $x) {
                $raw = is_string($x) ? self::base64url($x) : null;
                if ($raw !== null && strlen($raw) === 32) {
                    $keys[(string) $kid] = $raw;
                }
            }
            $decoded['keys'] = $keys;
            if (!is_numeric($decoded['fetchedAt'] ?? null) || !is_numeric($decoded['expiresAt'] ?? null)) {
                return null;
            }
            return $this->keySet = ['keys' => $keys, 'fetchedAt' => (float) $decoded['fetchedAt'], 'expiresAt' => (float) $decoded['expiresAt']];
        }
        return is_string($decoded['issuer'] ?? null) && is_string($decoded['jwks_uri'] ?? null)
            ? ['issuer' => $decoded['issuer'], 'jwks_uri' => $decoded['jwks_uri']]
            : null;
    }

    /** @param array<string, mixed> $value */
    private function store(string $name, array $value, int $ttl): void
    {
        if ($this->cache === null) {
            return;
        }
        if ($name === 'jwks') {
            $value['keys'] = array_map(static fn (string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '='), $value['keys']);
        }
        $this->cache->set(self::CACHE_PREFIX . $name . '.' . md5($this->baseUrl), json_encode($value, JSON_THROW_ON_ERROR), $ttl);
    }

    private static function invalid(string $message): BydevException
    {
        return new BydevException(Codes::TOKEN_INVALID, $message);
    }

    private static function json(string $text): mixed
    {
        try {
            return json_decode($text, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
    }

    private static function base64url(string $text): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/', $text) !== 1) {
            return null;
        }
        $decoded = base64_decode(strtr($text, '-_', '+/') . str_repeat('=', (4 - strlen($text) % 4) % 4), true);
        return $decoded === false ? null : $decoded;
    }
}
