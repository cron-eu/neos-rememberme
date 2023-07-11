<?php

namespace CRON\RememberMe\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

/**
 * An authentication token used to fetch JWT credentials from a cookie
 */
class RememberMe extends AbstractToken
{
    /**
     * @Flow\InjectConfiguration(path="cookie")
     * @var array
     */
    protected $cookie;

    /**
     * The jwt credentials
     *
     * @var array
     * @Flow\Transient
     */
    protected $credentials = ['jwt' => ''];

    /**
     * @param ActionRequest $actionRequest The current action request
     * @return boolean
     * @throws InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $cookieParams = $actionRequest->getHttpRequest()->getCookieParams();

        $cookieValue = $cookieParams[$this->cookie['name']] ?? null;

        if (empty($cookieValue)) {
            $this->setAuthenticationStatus(self::NO_CREDENTIALS_GIVEN);
            return false;
        }

        // only mark this token if it hasn't been successfully authenticated yet.
        // this will avoid re-authentication with every request.
        // Flow keeps this token with status AUTHENTICATION_SUCCESSFUL in the session after successful authentication.
        if ($this->getAuthenticationStatus() !== self::AUTHENTICATION_SUCCESSFUL) {
            $this->credentials['jwt'] = $cookieValue;
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }
    }

    /**
     * Returns a string representation of the token for logging purposes.
     *
     * @return string The username credential
     */
    public function __toString()
    {
        return 'JWT: "' . substr($this->credentials['jwt'], 0, 10) . '..."';
    }
}
