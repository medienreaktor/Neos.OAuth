<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\OAuth\Domain\Model\TokenType;
use Neos\OAuth\Domain\Repository\TokenRecordRepository;

/**
 * Revokes the codes and tokens issued for an account, e.g. when its password changes or it is deleted
 *
 * Tokens name their account only by its identifier, which a new account may take over once the old one is deleted.
 * So everything issued for an account must be revoked when it goes away, see {@see \Neos\OAuth\Security\AccountChangesAspect}
 *
 * A refresh token's record doesn't say which access token it belongs to, so the calling client's refresh token can't be
 * told apart from the others and is revoked as well: only the excepted access token stays valid until it expires
 */
#[Flow\Scope('singleton')]
final readonly class AccountTokens
{
    public function __construct(
        private TokenRecordRepository $tokenRecordRepository,
        private PersistenceManagerInterface $persistenceManager,
    ) {
    }

    /**
     * @param string|null $exceptAccessToken the identifier of an access token to keep, e.g. the one of the current request
     * @return int how many were revoked
     */
    public function revokeAllOf(string $accountIdentifier, ?string $exceptAccessToken = null): int
    {
        $revoked = 0;
        foreach ($this->tokenRecordRepository->findActive(null, $accountIdentifier, new \DateTimeImmutable()) as $record) {
            if ($record->getType() === TokenType::ACCESS_TOKEN && $record->getIdentifier() === $exceptAccessToken) {
                continue;
            }
            $record->revoke();
            $this->tokenRecordRepository->update($record);
            $revoked++;
        }
        $this->persistenceManager->persistAll();
        return $revoked;
    }
}
