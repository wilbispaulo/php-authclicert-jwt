<?php

declare(strict_types=1);

namespace AuthCliJWT;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

class StandardClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
