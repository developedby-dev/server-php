<?php

declare(strict_types=1);

namespace Bydev;

/**
 * 실패 하나 — `errorCode`로 분기한다(`Codes::*`). 메시지는 보여 주기만 한다. PHP 예외의 정수 `getCode()`와 겹치지 않게 이름을 따로 둔다.
 */
final class BydevException extends \RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly ?int $httpStatus = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
