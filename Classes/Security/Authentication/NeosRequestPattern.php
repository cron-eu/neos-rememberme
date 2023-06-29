<?php

/**
 *This is a request pattern that can detect and match "frontend" and "backend" mode
 */

declare(strict_types=1);

namespace CRON\RememberMe\Security\Authentication;

use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\RequestInterface;
use Neos\Flow\Security\RequestPatternInterface;

class NeosRequestPattern implements RequestPatternInterface
{
    /**
     * @var array
     */
    protected array $options;

    /**
     * Expects options in the form array('matchFrontend' => TRUE/FALSE)
     *
     * @param array $options
     */
    public function __construct(array $options)
    {
        $this->options = $options;
    }

    /**
     * Matches a \Neos\Flow\Mvc\RequestInterface against its set pattern rules
     *
     * @param ActionRequest $request The request that should be matched
     * @return bool TRUE if the pattern matched, FALSE otherwise
     */
    public function matchRequest(ActionRequest $request): bool
    {
        $shouldMatchFrontend = isset($this->options['matchFrontend']) && $this->options['matchFrontend'] === true;
        $requestPath = $request->getHttpRequest()->getUri()->getPath();
        $requestPathMatchesBackend = strpos($requestPath, '/neos') === 0 || strpos($requestPath, '@') !== false;
        return $shouldMatchFrontend !== $requestPathMatchesBackend;
    }
}
