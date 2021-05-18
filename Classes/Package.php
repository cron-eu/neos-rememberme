<?php

namespace CRON\RememberMe;

use Neos\Flow\Annotations as Flow;
use CRON\RememberMe\Neos\AuthenticationEventsHandler;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Package\Package as BasePackage;
use Neos\Flow\Security\Authentication\AuthenticationProviderManager;
use Neos\Flow\Security\Authentication\TokenInterface;

class Package extends BasePackage
{
    /**
     * @Flow\Inject
     * @var ObjectManagerInterface
     */
    protected $objectManager;

    /**
     * @param Bootstrap $bootstrap The current bootstrap
     * @return void
     */
    public function boot(Bootstrap $bootstrap)
    {
        $dispatcher = $bootstrap->getSignalSlotDispatcher();

        $dispatcher->connect(
            AuthenticationProviderManager::class, 'loggedOut',
            function() use ($bootstrap) {
                $authenticationEventsHandler = $bootstrap->getObjectManager()->get(AuthenticationEventsHandler::class);
                $authenticationEventsHandler->loggedOut($bootstrap);
            }
        );

        $dispatcher->connect(
            AuthenticationProviderManager::class, 'authenticatedToken',
            function(TokenInterface $token) use ($bootstrap) {
                $authenticationEventsHandler = $bootstrap->getObjectManager()->get(AuthenticationEventsHandler::class);
                $authenticationEventsHandler->authenticatedToken($token, $bootstrap);
            }
        );
    }
}
