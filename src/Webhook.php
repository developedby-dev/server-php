<?php

declare(strict_types=1);

namespace Bydev;

/** 웹훅 서명 검증 (명세 12절 · 안내서 11장 — Standard Webhooks v1). */
final class Webhook
{
    /**
     * `$rawBody`는 **받은 그대로의 본문**이다 — `json_decode`했다가 다시 만든 글자는 서명이 맞지 않는다(`file_get_contents('php://input')`).
     * 시크릿을 교체하는 중이면 둘 다 넘긴다. 헤더 이름의 대소문자는 가리지 않고, 값이 배열(PSR-7 `getHeaders()`)이면 첫 값을 쓴다.
     *
     * @param list<string> $secrets
     * @param array<string, string|list<string>> $headers
     * @param int|null $now 지금(Unix 초) — 시험에서 준다
     * @throws BydevException WEBHOOK_INVALID · 시크릿 형식이 틀리면 CONFIGURATION
     */
    public static function verify(array $secrets, array $headers, string $rawBody, ?int $now = null): WebhookVerification
    {
        $lowered = [];
        foreach ($headers as $name => $value) {
            $lowered[strtolower((string) $name)] = is_array($value) ? (string) ($value[0] ?? '') : (string) $value;
        }
        $id = $lowered['webhook-id'] ?? '';
        $timestamp = $lowered['webhook-timestamp'] ?? '';
        $signatures = $lowered['webhook-signature'] ?? '';
        if ($id === '' || $timestamp === '' || $signatures === '') {
            throw new BydevException(Codes::WEBHOOK_INVALID, '웹훅 헤더(webhook-id · webhook-timestamp · webhook-signature)가 없다');
        }
        if (!ctype_digit($timestamp) || abs(($now ?? time()) - (int) $timestamp) > Rules::WEBHOOK_TOLERANCE_SEC) {
            throw new BydevException(Codes::WEBHOOK_INVALID, '웹훅 시각이 허용 범위 밖이다 — 재전송 공격일 수 있다');
        }
        $candidates = [];
        foreach (explode(' ', $signatures) as $entry) {
            [$version, $value] = array_pad(explode(',', $entry, 2), 2, '');
            if ($version !== Rules::WEBHOOK_SIGNATURE_VERSION || $value === '') {
                continue;
            }
            $decoded = base64_decode($value, true);
            if ($decoded !== false) {
                $candidates[] = $decoded;
            }
        }
        $signed = $id . '.' . $timestamp . '.' . $rawBody;
        foreach ($secrets as $secret) {
            if (!str_starts_with($secret, Rules::WEBHOOK_SECRET_PREFIX)) {
                throw new BydevException(Codes::CONFIGURATION, '웹훅 시크릿은 ' . Rules::WEBHOOK_SECRET_PREFIX . '로 시작한다');
            }
            $key = base64_decode(substr($secret, strlen(Rules::WEBHOOK_SECRET_PREFIX)), true);
            if ($key === false) {
                throw new BydevException(Codes::CONFIGURATION, '웹훅 시크릿을 읽지 못했다');
            }
            $expected = hash_hmac('sha256', $signed, $key, true);
            foreach ($candidates as $candidate) {
                if (hash_equals($expected, $candidate)) {
                    return new WebhookVerification($id, (int) $timestamp);
                }
            }
        }
        throw new BydevException(Codes::WEBHOOK_INVALID, '웹훅 서명이 맞지 않는다');
    }
}
