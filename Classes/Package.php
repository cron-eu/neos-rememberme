<?php

namespace CRON\RememberMe;

use Neos\Flow\Annotations as Flow;
use CRON\RememberMe\Neos\AuthenticationEventsHandler;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Mvc\Dispatcher;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Package\Package as BasePackage;
use Neos\Flow\Security\Authentication\AuthenticationProviderManager;

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
            AuthenticationProviderManager::class,
            'loggedOut',
            AuthenticationEventsHandler::class,
            'loggedOut'
        );

        $dispatcher->connect(
            AuthenticationProviderManager::class,
            'authenticatedToken',
            AuthenticationEventsHandler::class,
            'authenticatedToken'
        );

        $dispatcher->connect(Dispatcher::class,
            'beforeControllerInvocation',
            AuthenticationEventsHandler::class,
            'handleBeforeControllerInvocation'
        );

        $dispatcher->connect(Dispatcher::class,
            'afterControllerInvocation',
            AuthenticationEventsHandler::class,
            'handleAfterControllerInvocation'
        );
    }
}
