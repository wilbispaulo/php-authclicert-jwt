<?php

namespace Wilbis\AuthCliJWT;

use Exception;
use src\StandardClock;
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

class OAuthCli
{
    private $publicKey = null;
    private array $claims = [];

    public function __construct()
    {
        if (count($cer = glob(CERT . '*.cer')) > 0) {
            $this->publicKey = JWKFactory::createFromCertificateFile($cer[0]);
            $this->setPublicCER($cer[0]);
        };
    }

    public function loadJWS(string $tokenJws): array
    {
        try {
            $jws = (new JWSSerializerManager([
                new CompactSerializer(),
            ]))->unserialize($tokenJws);
            $jwsVerifier = new JWSVerifier(new AlgorithmManager([
                new RS256(),
            ]));

            if (!$jwsVerifier->verifyWithKey($jws, $this->publicKey, 0)) {
                return ['error' => 'signature_invalid'];
            }

            $claims = $this->checkClaims($jws);

            if (array_key_exists('error', $claims)) {
                $claims['token_status'] = 'invalid';

                return $claims;
            }
            $this->setClaims($claims);
            return ['token_status' => 'valid'];
        } catch (Exception $e) {
            return ['token_status' => 'fail'];
        }
    }

    private function setPublicCER(string $pathToCER)
    {
        $this->publicKey = JWKFactory::createFromCertificateFile($pathToCER);
        // var_dump($publicKey);
    }

    private function setPublicKeyP12(string $pathToCer)
    {
        $publicKey = openssl_pkey_get_public(file_get_contents($pathToCer));
        $this->publicKey = openssl_pkey_get_details($publicKey)['key'];
    }

    public function setClaims(array $claims)
    {
        $this->claims = $claims;
    }

    public function getClaims()
    {
        return $this->claims;
    }


    public function checkOAuth(): array
    {
        if ($token = self::getBearerToken()) {
            $result = $this->loadJWS($token);
            // if (array_key_exists('error', $result)) {
            //     return $result;
            // }
            // return ['auth_status' => 'ok'];
            return $result;
        } else {
            return [
                'response' => 'TOKEN_NOT_FOUND'
            ];
        };
    }

    private function checkClaims(JWS $jws): array
    {
        $claims = json_decode(($jws->getPayload()), true);
        // $claims['iss'] = $this->checkIssuer($claims);
        // $claims['exp'] = $this->checkExpiration($claims);
        // $claims['iat'] = $this->checkIssuedAt($claims);
        // $claims['nbf'] = $this->checkNotBefore($claims);
        $clock = new StandardClock;
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new ExpirationTimeChecker($clock),
                new IssuedAtChecker($clock),
                new NotBeforeChecker($clock),
                new IssuerChecker([
                    $_ENV['ISSUER'],
                ]),
                new AudienceChecker($_ENV['AUDIENCE']),
            ]
        );
        try {
            $checkClaim = $claimCheckerManager->check($claims);
            $checkClaim['scope'] = $claims['scope'];
            return $checkClaim;
        } catch (InvalidClaimException $e) {
            return ['error' => $e->getMessage()];
        }
    }

    private function checkExpiration(array $claims): string
    {
        $clock = new StandardClock;
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new ExpirationTimeChecker($clock),
            ]
        );
        try {
            return $claimCheckerManager->check($claims);
        } catch (Exception $e) {
            return 'EXPIRED';
        }
    }

    private function checkIssuedAt(array $claims): string
    {
        $clock = new StandardClock;
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new IssuedAtChecker($clock),
            ]
        );
        try {
            return $claimCheckerManager->check($claims);
        } catch (Exception $e) {
            return 'INVALID';
        }
    }

    private function checkNotBefore(array $claims): string
    {
        $clock = new StandardClock;
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new NotBeforeChecker($clock),
            ]
        );
        try {
            return $claimCheckerManager->check($claims);
        } catch (Exception $e) {
            return 'INVALID';
        }
    }

    private function checkIssuer(array $claims): string
    {
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new IssuerChecker([
                    'teste',
                ]),
            ]
        );
        try {
            return $claimCheckerManager->check($claims);
        } catch (Exception $e) {
            return 'INVALID';
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
