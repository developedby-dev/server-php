<?php

declare(strict_types=1);

namespace Bydev;

/** 검증된 licenseToken 클레임 (명세 9 · 12절). */
final readonly class LicenseClaims
{
    public function __construct(
        public string $iss,
        public string $sub,
        public string $aud,
        public string $productId,
        public string $deviceId,
        public string $sid,
        public int $generation,
        public int $iat,
        public int $exp,
        /** 세션을 얻을 때 앱이 보낸 대상 · 버전으로 데브가 확정한 빌드(ADR-0049). 확정하지 못했으면 null */
        public ?string $buildId = null,
    ) {
    }

    /** @param array<string, mixed> $c */
    public static function read(array $c): self
    {
        return new self(
            Claims::text($c, 'iss'),
            Claims::text($c, 'sub'),
            Claims::text($c, 'aud'),
            Claims::text($c, 'product_id'),
            Claims::text($c, 'device_id'),
            Claims::text($c, 'sid'),
            Claims::integer($c, 'generation'),
            Claims::integer($c, 'iat'),
            Claims::integer($c, 'exp'),
            Claims::optionalText($c, 'build_id'),
        );
    }
}
