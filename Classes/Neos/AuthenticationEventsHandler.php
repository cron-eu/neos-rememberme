<?php

namespace CRON\RememberMe\Neos;

use Neos\Flow\Annotations as Flow;
use Firebase\JWT\JWT as JwtService;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Cryptography\HashService;

/**
 * @Flow\Scope("singleton")
 */
class AuthenticationEventsHandler
{
    /**
     * @Flow\InjectConfiguration(path="cookie")
     * @var array
     */
    protected $cookie;

    /**
     * @Flow\Inject
     * @var HashService
     */
    protected $hashService;

    /**
     * @Flow\Inject
     * @var ObjectManagerInterface
     */
    protected $objectManager;

    /**
     * expire JWT cookie when the user logs out
     */
    public function loggedOut(Bootstrap $bootstrap): void
    {
        $requestHandler = $bootstrap->getActiveRequestHandler();
        // not a HTTP request handler? => none of our business
        if (!$requestHandler instanceof HttpRequestHandlerInterface) {
            return;
        }

        $jwtCookie = new Cookie($this->cookie['name']);
        $jwtCookie->expire();
        $requestHandler->getHttpResponse()->setCookie($jwtCookie);
    }

    /**
     * @param TokenInterface $token
     */
    public function authenticatedToken(TokenInterface $token, Bootstrap $bootstrap): void
    {
        $requestHandler = $bootstrap->getActiveRequestHandler();
        // not a HTTP request handler? => none of our business
        if (!$requestHandler instanceof HttpRequestHandlerInterface) {
            return;
        }

        $credentials = $token->getCredentials();

        if (isset($credentials['rememberMe']) && $credentials['rememberMe']) {
            $account = $token->getAccount();

            $jwtPayload = [
                'accountIdentifier' => $account->getAccountIdentifier(),
                'accountRoleIdentifiers' => array_keys($account->getRoles()),
            ];
            $jwtExpiration = isset($this->cookie['lifetime']) ? time() + (integer)$this->cookie['lifetime'] : 0;
            if ($jwtExpiration > 0) {
                $jwtPayload['exp'] = $jwtExpiration;
            }
            // Don't be surprised by the hard-coded "jwt". That is *not* the secret key of the JWT. HashService::generateHmac() uses the encryption key of this installation
            $jwtKey = $this->hashService->generateHmac('jwt');
            $jwt = JwtService::encode($jwtPayload, $jwtKey, 'HS256');
            $jwtCookie = new Cookie($this->cookie['name'], $jwt, $jwtExpiration);
            $requestHandler->getHttpResponse()->setCookie($jwtCookie);
            return;
        }
    }
}
