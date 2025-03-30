<?php

declare(strict_types=1);

namespace Wilbis\AuthCliJwt;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

final class ScopeChecker implements ClaimChecker
{
    private const CLAIM_NAME = 'scope';

    public function __construct(
        private string $endpoint
    ) {}
    public function checkClaim(mixed $value): void
    {
        if (is_null($value)) {
            throw new InvalidClaimException('The claim "scope" is missing', 'scope', $value);
        }

        if (!is_array($value)) {
            throw new InvalidClaimException('The claim "scope" must be a array of endpoints.', 'scope', $value);
        }

        $t = false;
        foreach ($value as $key => $val) {
            $t |= ($this->endpoint === ($key . '/' . $val));
        }

        if (!$t) {
            throw new InvalidClaimException('endpoint_not_found', 'scope', $value);
        }
    }

    public function supportedClaim(): string
    {
        return ScopeChecker::CLAIM_NAME;
    }
}
