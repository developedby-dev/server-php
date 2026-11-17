<?php

declare(strict_types=1);

namespace Bydev;

/** @internal 클레임 읽기 — 모양이 다르면 TOKEN_INVALID. */
final class Claims
{
    /** @param array<string, mixed> $c */
    public static function text(array $c, string $key): string
    {
        $value = $c[$key] ?? null;
        if (!is_string($value)) {
            throw new BydevException(Codes::TOKEN_INVALID, "클레임 {$key}가 문자열이 아니다");
        }
        return $value;
    }

    /** @param array<string, mixed> $c 없으면 null, 있는데 문자열이 아니면 TOKEN_INVALID */
    public static function optionalText(array $c, string $key): ?string
    {
        return ($c[$key] ?? null) === null ? null : self::text($c, $key);
    }

    /** @param array<string, mixed> $c */
    public static function integer(array $c, string $key): int
    {
        $value = $c[$key] ?? null;
        if (!is_int($value)) {
            throw new BydevException(Codes::TOKEN_INVALID, "클레임 {$key}가 정수가 아니다");
        }
        return $value;
    }
}
