<?php

namespace CRON\RememberMe\Security\Authentication;

use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\TokenInterface;

interface RememberMeAuthenticationProcessorInterface
{

    /**
     * This interface method will be called after the JWT was decoded in the RememberMeProvider.
     * Implement this interface and configure the implemented class name in CRON.RememberMe.rememberMeAuthenticationProcessorClassName.
     * Use it for example to check and update the roles or check if the account was deleted in the meantime.
     * Assign the account to the token: $token->setAccount($account);
     * and set the authentication status: $token->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
     * if the login via RememberMe should be successful.
     *
     * @param Account $account
     * @param TokenInterface $token
     * @param array $data
     */
    public function process(Account $account, TokenInterface $token, array $data): void;
}
