<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Security;

use Neos\Flow\Tests\FunctionalTestCase;
use Neos\Neos\Domain\Model\User;
use Neos\Neos\Domain\Service\UserService;
use Neos\OAuth\Domain\Model\TokenRecord;
use Neos\OAuth\Domain\Model\TokenType;
use Neos\OAuth\Domain\Repository\TokenRecordRepository;
use PHPUnit\Framework\Attributes\Test;

/**
 * Changes of a user made through Neos' UserService, as the backend modules and the CLI do, revoke its tokens
 */
class AccountChangesAspectTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();
        $userService = $this->objectManager->get(UserService::class);
        $this->user = $userService->createUser('editor', 'password', 'Ed', 'Itor', ['Neos.Neos:Editor'], 'Neos.Neos:Backend');
        $userService->createUser('other', 'password', 'Oth', 'Er', ['Neos.Neos:Editor'], 'Neos.Neos:Backend');
        $tokenRecordRepository = $this->objectManager->get(TokenRecordRepository::class);
        foreach (['editor', 'other'] as $accountIdentifier) {
            foreach ([TokenType::ACCESS_TOKEN, TokenType::REFRESH_TOKEN, TokenType::AUTH_CODE] as $type) {
                $tokenRecordRepository->add(new TokenRecord($accountIdentifier . '-' . $type->value, $type, 'spa', $accountIdentifier, new \DateTimeImmutable('+1 hour')));
            }
        }
        $this->persistenceManager->persistAll();
    }

    #[Test]
    public function changingThePasswordRevokesTheUsersTokens(): void
    {
        $this->objectManager->get(UserService::class)->setUserPassword($this->user, 'new-password');

        self::assertSame([], $this->activeTokensOf('editor'));
        self::assertCount(3, $this->activeTokensOf('other'));
    }

    #[Test]
    public function deactivatingTheUserRevokesItsTokens(): void
    {
        $this->objectManager->get(UserService::class)->deactivateUser($this->user);

        self::assertSame([], $this->activeTokensOf('editor'));
        self::assertCount(3, $this->activeTokensOf('other'));
    }

    /**
     * @return list<string>
     */
    private function activeTokensOf(string $accountIdentifier): array
    {
        $this->persistenceManager->clearState();
        return array_map(
            static fn (TokenRecord $record) => $record->getIdentifier(),
            $this->objectManager->get(TokenRecordRepository::class)->findActive(null, $accountIdentifier, new \DateTimeImmutable()),
        );
    }
}
