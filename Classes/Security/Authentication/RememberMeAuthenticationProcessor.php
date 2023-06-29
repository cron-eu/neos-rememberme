<?php

namespace CRON\RememberMe\Security\Authentication;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Configuration\Exception\InvalidConfigurationTypeException;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception;
use Neos\Flow\Security\Exception\NoSuchRoleException;
use Neos\Flow\Security\Policy\PolicyService;

class RememberMeAuthenticationProcessor implements RememberMeAuthenticationProcessorInterface
{
    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected PolicyService $policyService;

    /**
     * @param Account $account
     * @param TokenInterface $token
     * @param array $data
     * @throws NoSuchRoleException
     * @throws InvalidConfigurationTypeException
     * @throws Exception
     */
    public function process(Account $account, TokenInterface $token, array $data): void
    {
        if (isset($data['accountRoleIdentifiers'])) {
            foreach ($data['accountRoleIdentifiers'] as $roleIdentifier) {
                $account->addRole($this->policyService->getRole($roleIdentifier));
            }
        }

        $token->setAccount($account);
        $token->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
    }
}
