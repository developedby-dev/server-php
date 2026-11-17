<?php

declare(strict_types=1);

namespace Bydev;

/** 검증된 웹훅의 id와 시각(Unix 초) — 중복 수신은 id로 거른다. */
final readonly class WebhookVerification
{
    public function __construct(public string $id, public int $timestamp)
    {
    }
}
