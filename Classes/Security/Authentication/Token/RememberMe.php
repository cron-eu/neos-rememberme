<?php

namespace CRON\RememberMe\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;

/**
 * An authentication token used to fetch JWT credentials from a cookie
 */
class RememberMe extends AbstractToken implements SessionlessTokenInterface
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
     * @return void
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $jwtCookie = $actionRequest->getHttpRequest()->getCookie($this->cookie['name']);
        if ($jwtCookie === null) {
            return;
        }
        $this->credentials['jwt'] = $jwtCookie->getValue();
        $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
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