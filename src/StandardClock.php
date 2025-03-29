<?php

declare(strict_types=1);

namespace src\library;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

class StandardClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
