<?php

namespace Wilbis\AuthCliJWT;

use Exception;
use Wilbis\AuthCliJWT\StandardClock;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Signature\JWS;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Wilbis\AuthCliJwt\ScopeChecker;

class OAuthCli
{
    private string $endpoint;
    private $publicKey = null;
    private array $claims = [];

    public function __construct(
        private string $pathToCert,
        private string $issuer,
        private string $audience
    ) {
        if (count($cer = glob($pathToCert)) > 0) {
            $this->publicKey = JWKFactory::createFromCertificateFile($cer[0]);
            $this->setPublicCER($cer[0]);
        };
    }

    public function checkOAuth(string $endpoint): array
    {
        $this->endpoint = $endpoint;
        if ($token = self::getBearerToken()) {
            return $this->loadJWS($token);
        } else {
            return [
                'error' => 'token_is_missing',
                'error_description' => 'The bearer token is missing in request.'
            ];
        };
    }

    public function getClaims()
    {
        return $this->claims;
    }

    private function loadJWS(string $tokenJws): array
    {
        try {
            $jws = (new JWSSerializerManager([
                new CompactSerializer(),
            ]))->unserialize($tokenJws);
            $jwsVerifier = new JWSVerifier(new AlgorithmManager([
                new RS256(),
            ]));

            if (!$jwsVerifier->verifyWithKey($jws, $this->publicKey, 0)) {
                return [
                    'error' => 'signature_invalid',
                    'error_description' => 'The token is not valid. Failed signature verification.',
                ];
            }

            $claims = $this->checkClaims($jws);

            if (array_key_exists('error', $claims)) {
                $claims['error_description'] = 'The token is not valid. Failed claim check';

                return $claims;
            }
            $this->claims = $claims;
            return array_merge($claims, ['token_status' => 'valid']);
        } catch (Exception $e) {
            return [
                'token_status' => 'fail',
                'error' => $e->getMessage(),
            ];
        }
    }

    private function setPublicCER(string $pathToCER)
    {
        $this->publicKey = JWKFactory::createFromCertificateFile($pathToCER);
    }

    private function checkClaims(JWS $jws): array
    {
        $claims = json_decode(($jws->getPayload()), true);
        $clock = new StandardClock;
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new ExpirationTimeChecker($clock),
                new IssuedAtChecker($clock),
                new NotBeforeChecker($clock),
                new IssuerChecker([
                    $this->issuer,
                ]),
                new AudienceChecker($this->audience),
                new ScopeChecker($this->endpoint)
            ]
        );
        try {
            $checkClaim = $claimCheckerManager->check($claims);
            return array_merge(['access' => 'allowed'], $checkClaim);
        } catch (InvalidClaimException $e) {
            return [
                'access' => 'denied',
                'error' => $e->getMessage()
            ];
        }
    }

    public static function getBearerToken(): string | false
    {
        $headers = apache_request_headers();
        if (isset($headers['Authorization'])) {
            preg_match('/Bearer(?P<token>.*)/', $headers['Authorization'], $token);
            return trim($token['token']);
        }
        return false;
    }
}
