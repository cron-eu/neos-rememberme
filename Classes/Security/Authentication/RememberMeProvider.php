<?php

namespace CRON\RememberMe\Security\Authentication;

use Neos\Flow\Annotations as Flow;
use CRON\RememberMe\Security\Authentication\Token\RememberMe;
use Firebase\JWT\JWT as JwtService;
use Neos\Flow\Log\SystemLoggerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\InvalidArgumentForHashGenerationException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

/**
 * An authentication provider that authenticates Jwt and UsernamePassword tokens.
 */
class RememberMeProvider extends AbstractProvider
{

    /**
     * @Flow\Inject
     * @var HashService
     */
    protected $hashService;

    /**
     * @Flow\Inject
     * @var SystemLoggerInterface
     */
    protected $systemLogger;

    /**
     * @Flow\InjectConfiguration(path="rememberMeAuthenticationProcessorClassName")
     * @var array
     */
    protected $rememberMeAuthenticationProcessorClassName;

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames()
    {
        return [RememberMe::class];
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @return void
     * @throws UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if ($authenticationToken instanceof RememberMe) {
            $this->authenticateRememberMeToken($authenticationToken);
        } else {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1461748226);
        }
    }

    /**
     * @param RememberMe $token
     * @throws InvalidArgumentForHashGenerationException
     * @throws InvalidAuthenticationStatusException
     */
    protected function authenticateRememberMeToken(RememberMe $token)
    {
        $credentials = $token->getCredentials();
        if (!is_array($credentials) || !isset($credentials['jwt'])) {
            $token->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            return;
        }
        // Don't be surprised by the hard-coded "jwt". That is *not* the secret key of the JWT. HashService::generateHmac() uses the encryption key of this installation
        $jwtKey = $this->hashService->generateHmac('jwt');
        $jwtPayload = null;
        try {
            $jwtPayload = (array)JwtService::decode($credentials['jwt'], $jwtKey, ['HS256']);
        } catch (\Exception $exception) {
            $this->systemLogger->logException($exception);
            $token->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }
        if ($jwtPayload === null || !isset($jwtPayload['accountIdentifier'])) {
            $token->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        $account = new Account();
        $account->setAccountIdentifier($jwtPayload['accountIdentifier']);
        $account->setAuthenticationProviderName($this->name);

        if (empty($this->rememberMeAuthenticationProcessorClassName)) {
            throw new \Exception('Setting CRON.RememberMe.rememberMeAuthenticationProcessorClassName is not set.');
        }

        $rememberMeAuthenticationProcessor = new $this->rememberMeAuthenticationProcessorClassName();

        if (!$rememberMeAuthenticationProcessor instanceof RememberMeAuthenticationProcessorInterface) {
            throw new \Exception(sprintf('Class "%s" should implement RememberMeAuthenticationProcessorInterface but does not.', $this->rememberMeAuthenticationProcessorClassName));
        }

        $rememberMeAuthenticationProcessor->process($account, $token, $jwtPayload);
    }
}
