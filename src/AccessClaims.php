<?php

declare(strict_types=1);

namespace Bydev;

/** 검증된 access_token 클레임 (명세 12절). `sub`가 그 판매자용 가명 식별자다. */
final readonly class AccessClaims
{
    public function __construct(
        public string $iss,
        public string $sub,
        public string $aud,
        public string $clientId,
        public string $scope,
        public int $iat,
        public int $exp,
        public string $jti,
    ) {
    }

    /** @param array<string, mixed> $c */
    public static function read(array $c): self
    {
        return new self(
            Claims::text($c, 'iss'),
            Claims::text($c, 'sub'),
            Claims::text($c, 'aud'),
            Claims::text($c, 'client_id'),
            Claims::text($c, 'scope'),
            Claims::integer($c, 'iat'),
            Claims::integer($c, 'exp'),
            Claims::text($c, 'jti'),
        );
    }
}
