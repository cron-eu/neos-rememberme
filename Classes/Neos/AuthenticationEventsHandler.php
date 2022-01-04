<?php

namespace CRON\RememberMe\Neos;

use Neos\Flow\Annotations as Flow;
use Firebase\JWT\JWT as JwtService;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\ActionResponse;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\InvalidArgumentForHashGenerationException;

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
     * jwt cookie to be sent in the `handleBeforeControllerInvocation` hook
     *
     * @var Cookie
     */
    private $setJwtCookie = null;

    /**
     * jwt cookie to be sent in the `handleAfterControllerInvocation` hook
     *
     * @var Cookie
     */
    private $expireJwtCookie = null;

    /**
     * expire JWT cookie when the user logs out
     */
    public function loggedOut(): void
    {
        $this->expireJwtCookie = new Cookie($this->cookie['name']);
        $this->expireJwtCookie->expire();
    }

    /**
     * See Package.php
     *
     * @param TokenInterface $token
     * @throws InvalidArgumentForHashGenerationException
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
            $this->setJwtCookie = new Cookie($this->cookie['name'], $jwt, $jwtExpiration);
            // the cookie will be set via the `handleHTTPResponse` hook later on
        }
    }

    /**
     * Inject the jwt cookie into the current http response if needed
     * @param mixed $request of type Neos\Flow\Mvc\ActionRequest when coming from a web request, but of type Neos\Flow\Cli\Request when coming from a command
     * @param mixed $response of type Neos\Flow\Mvc\ActionResponse when coming from a web request, but of type Neos\Flow\Cli\Response when coming from a command
     * @param mixed $controller of type Neos\Flow\Mvc\Controller\ControllerInterface when coming from a web request, but of type Neos\Flow\Command\ConfigurationCommandController when coming from a command
     */
    public function handleBeforeControllerInvocation($request, $response, $controller): void
    {
        if ($this->setJwtCookie !== null && $this->expireJwtCookie == null && $response instanceof ActionResponse) {
            $response->setCookie($this->setJwtCookie);
            $this->setJwtCookie = null;
        }
    }

    /**
     * Inject the jwt cookie expiration into the current http response if needed
     * @param mixed $request of type Neos\Flow\Mvc\ActionRequest when coming from a web request, but of type Neos\Flow\Cli\Request when coming from a command
     * @param mixed $response of type Neos\Flow\Mvc\ActionResponse when coming from a web request, but of type Neos\Flow\Cli\Response when coming from a command
     * @param mixed $controller of type Neos\Flow\Mvc\Controller\ControllerInterface when coming from a web request, but of type Neos\Flow\Command\ConfigurationCommandController when coming from a command
     */
    public function handleAfterControllerInvocation($request, $response, $controller): void
    {
        if ($this->expireJwtCookie !== null && $response instanceof ActionResponse) {
            $response->setCookie($this->expireJwtCookie);
            $this->expireJwtCookie = null;
        }
    }
}
