<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Neos.OAuth: mark clients that registered themselves (RFC 7591), so the consent page says that nobody vouches for them
 */
final class Version20261117090000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add selfRegistered to the OAuth clients';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\AbstractMySQLPlatform,
            "Migration can only be executed safely on '\Doctrine\DBAL\Platforms\AbstractMySQLPlatform'."
        );

        $this->addSql('ALTER TABLE neos_oauth_domain_model_oauthclient ADD selfregistered TINYINT(1) DEFAULT 0 NOT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\AbstractMySQLPlatform,
            "Migration can only be executed safely on '\Doctrine\DBAL\Platforms\AbstractMySQLPlatform'."
        );

        $this->addSql('ALTER TABLE neos_oauth_domain_model_oauthclient DROP selfregistered');
    }
}
