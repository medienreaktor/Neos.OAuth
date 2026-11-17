<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Neos\Domain\Model\User;
use Neos\OAuth\Domain\AccountTokens;

/**
 * Revokes the OAuth codes and tokens of a Neos user's accounts when its password changes, or when it is deactivated or
 * deleted, whichever way that happens: backend modules, CLI or API all go through the UserService
 *
 * Neos ends the user's sessions in those cases, this does the same for tokens. Otherwise a token would outlive the
 * password reset meant to lock its holder out, and a deleted account's refresh token would keep working, even as a new
 * account that takes over the identifier
 *
 * The access token of the current request, if any, stays valid, so a client changing its user's password isn't cut off
 * in the middle of what it's doing
 */
#[Flow\Aspect]
class AccountChangesAspect
{
    #[Flow\Inject]
    protected AccountTokens $accountTokens;

    #[Flow\Inject]
    protected OAuthContext $oauthContext;

    #[Flow\Inject]
    protected SecurityContext $securityContext;

    #[Flow\AfterReturning('method(Neos\Neos\Domain\Service\UserService->(setUserPassword|deactivateUser|deleteUser)())')]
    public function revokeTokens(JoinPointInterface $joinPoint): void
    {
        $user = $joinPoint->getMethodArgument('user');
        if (!$user instanceof User) {
            return;
        }
        // there is no request to authenticate on the command line
        $exceptAccessToken = $this->securityContext->canBeInitialized()
            ? $this->oauthContext->authenticatedGrant()?->accessTokenIdentifier
            : null;
        foreach ($user->getAccounts() as $account) {
            /** @var Account $account */
            $this->accountTokens->revokeAllOf($account->getAccountIdentifier(), $exceptAccessToken);
        }
    }
}
