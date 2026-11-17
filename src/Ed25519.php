<?php

declare(strict_types=1);

namespace Bydev;

/** @internal Ed25519 서명 확인 — ext-sodium이 있으면 그것, 없으면 ext-openssl(PHP 8.4부터 Ed25519 키를 읽는다). */
final class Ed25519
{
    /** SubjectPublicKeyInfo(Ed25519)의 앞부분 — 뒤에 32바이트 공개키가 붙는다 (RFC 8410) */
    private const SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    /** 시험이 openssl 길을 고르려고 — null이면 저절로 */
    public static ?string $force = null;

    public static function opensslAvailable(): bool
    {
        return function_exists('openssl_verify') && PHP_VERSION_ID >= 80400;
    }

    public static function verify(string $signature, string $message, string $publicKey): bool
    {
        if (strlen($signature) !== 64 || strlen($publicKey) !== 32) {
            return false;
        }
        $useSodium = self::$force === null ? function_exists('sodium_crypto_sign_verify_detached') : self::$force === 'sodium';
        if ($useSodium) {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode(self::SPKI_PREFIX . $publicKey), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            return false;
        }
        // Ed25519는 미리 해시하지 않는다 — 알고리즘 0(기본 다이제스트 없음)
        return openssl_verify($message, $signature, $key, 0) === 1;
    }
}
