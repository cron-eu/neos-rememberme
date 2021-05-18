<?php

namespace CRON\RememberMe\Security\Authentication;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Policy\PolicyService;

class RememberMeAuthenticationProcessor implements RememberMeAuthenticationProcessorInterface
{
    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

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
