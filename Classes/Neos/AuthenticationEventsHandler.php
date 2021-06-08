<?php

namespace CRON\RememberMe\Neos;

use Neos\Flow\Annotations as Flow;
use Firebase\JWT\JWT as JwtService;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Mvc\ActionResponse;
use Neos\Flow\Mvc\Controller\ControllerInterface;
use Neos\Flow\Mvc\RequestInterface;
use Neos\Flow\Mvc\ResponseInterface;
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
     * jwt cookie to be send in the `handleHTTPResponse` hook
     *
     * @var Cookie
     */
    private $jwtCookie = null;

    /**
     * expire JWT cookie when the user logs out
     */
    public function loggedOut(): void
    {
        $this->jwtCookie = new Cookie($this->cookie['name']);
        $this->jwtCookie->expire();
    }

    /**
     * See Package.php
     *
     * @param TokenInterface $token
     */
    public function authenticatedToken(TokenInterface $token): void
    {
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
            $this->jwtCookie = new Cookie($this->cookie['name'], $jwt, $jwtExpiration);
            // the cookie will be set via the `handleHTTPResponse` hook later on
        }
    }

    /**
     * Inject the jwt cookie into the current http response if needed
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param ControllerInterface $controller
     */
    public function handleHTTPResponse(RequestInterface $request, ResponseInterface $response, ControllerInterface $controller): void
    {
        if ($this->jwtCookie !== null && $response instanceof ActionResponse) {
            $response->getHeaders()->setCookie($this->jwtCookie);
        }
    }

}
