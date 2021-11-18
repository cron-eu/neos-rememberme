<?php

namespace CRON\RememberMe\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Request as HttpRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Utility\ObjectAccess;

class UsernamePasswordWithRememberMe extends AbstractToken
{
    /**
     * @Flow\InjectConfiguration(package="CRON.RememberMe")
     * @var array
     */
    protected $settings = [];

    /**
     * The username/password/rememberMe credentials
     * @var array
     * @Flow\Transient
     */
    protected $credentials = ['username' => '', 'password' => '', 'rememberMe' => false];

    /**
     * Updates the username and password credentials from the POST vars, if the POST parameters
     * are available. Sets the authentication status to REAUTHENTICATION_NEEDED, if credentials have been sent.
     *
     * Note: You need to send the username, password and rememberMe (optional) in POST parameters configured in
     * CRON.RememberMe.loginFormField
     *
     * @param ActionRequest $actionRequest The current action request
     * @return bool
     *
     * @throws InvalidAuthenticationStatusException
     * @throws \Neos\Flow\Configuration\Exception
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $httpRequest = $actionRequest->getHttpRequest();
        if ($httpRequest->getMethod() !== 'POST') {
            return false;
        }

        $referringRequest = $actionRequest->getReferringRequest();
        if (!$referringRequest instanceof ActionRequest) {
            return false;
        }
        $parentRequest = $referringRequest->getParentRequest();
        if (!$parentRequest instanceof ActionRequest && !$parentRequest instanceof HttpRequest) {
            return false;
        }

        $arguments = $parentRequest->getArguments();

        foreach ($this->settings['loginFormFields'] as $loginFormFieldsSetting) {
            if (empty($loginFormFieldsSetting['username']) || empty($loginFormFieldsSetting['password'])) {
                throw new \Neos\Flow\Configuration\Exception('You need to configure both username and password fields in every entry of CRON.RememberMe.loginFormFields');
            }

            $username = trim(ObjectAccess::getPropertyPath($arguments, $loginFormFieldsSetting['username']));
            $password = ObjectAccess::getPropertyPath($arguments, $loginFormFieldsSetting['password']);
            $rememberMe = !empty($loginFormFieldsSetting['rememberMe']) ? ObjectAccess::getPropertyPath($arguments, $loginFormFieldsSetting['rememberMe']) : null;

            if (!empty($username) && !empty($password)) {
                $this->credentials['username'] = $username;
                $this->credentials['password'] = $password;
                $this->credentials['rememberMe'] = $rememberMe;
                $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
                break;
            }
        }

        return true;
    }

    /**
     * Returns a string representation of the token for logging purposes.
     *
     * @return string The username credential
     */
    public function __toString()
    {
        return 'Username: "' . $this->credentials['username'] . '"';
    }
}
