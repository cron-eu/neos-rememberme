<?php

namespace CRON\RememberMe\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Configuration\Exception;
use Neos\Flow\Mvc\Exception\InvalidActionNameException;
use Neos\Flow\Mvc\Exception\InvalidArgumentNameException;
use Neos\Flow\Mvc\Exception\InvalidArgumentTypeException;
use Neos\Flow\Mvc\Exception\InvalidControllerNameException;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Exception\InvalidArgumentForHashGenerationException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Flow\Security\Exception\InvalidHashException;
use Neos\Utility\ObjectAccess;

class UsernamePasswordWithRememberMe extends AbstractToken
{
    /**
     * @Flow\InjectConfiguration(package="CRON.RememberMe")
     * @var array
     */
    protected array $settings = [];

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
     * @throws Exception
     * @throws InvalidActionNameException
     * @throws InvalidArgumentNameException
     * @throws InvalidArgumentTypeException
     * @throws InvalidControllerNameException
     * @throws InvalidArgumentForHashGenerationException
     * @throws InvalidHashException
     */
    public function updateCredentials(ActionRequest $actionRequest): bool
    {
        $httpRequest = $actionRequest->getHttpRequest();
        if ($httpRequest->getMethod() !== 'POST') {
            return false;
        }

        $referringRequest = $actionRequest->getReferringRequest();
        if (!$referringRequest instanceof ActionRequest) {
            return false;
        }

        $arguments = $referringRequest->getHttpRequest()->getParsedBody();

        if (empty($arguments)) {
            return false;
        }

        foreach ($this->settings['loginFormFields'] as $loginFormFieldsSetting) {
            if (empty($loginFormFieldsSetting['username']) || empty($loginFormFieldsSetting['password'])) {
                throw new Exception('You need to configure both username and password fields in every entry of CRON.RememberMe.loginFormFields');
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
