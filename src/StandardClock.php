<?php

declare(strict_types=1);

namespace AuthCliJwt;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

class StandardClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
