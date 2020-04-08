<?php

declare(strict_types=1);

namespace Kreait\Firebase\JWT\Tests;

use InvalidArgumentException;
use Kreait\Firebase\JWT\Action\VerifyIdToken\Handler;
use Kreait\Firebase\JWT\Contract\Token;
use Kreait\Firebase\JWT\IdTokenVerifier;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;
use stdClass;

/**
 * @internal
 */
final class IdTokenVerifierTest extends TestCase
{
    /** @var Handler|MockObject */
    private $handler;

    /** @var IdTokenVerifier */
    private $verifier;

    protected function setUp(): void
    {
        $this->handler = $this->createMock(Handler::class);

        $this->verifier = new IdTokenVerifier($this->handler);
    }

    /**
     * @test
     */
    public function it_can_be_created_with_a_project_id(): void
    {
        IdTokenVerifier::createWithProjectId('project-id');
        $this->addToAssertionCount(1);
    }

    /**
     * @test
     */
    public function it_can_be_created_with_a_project_id_and_custom_cache(): void
    {
        IdTokenVerifier::createWithProjectIdAndCache('project-id', $this->createMock(CacheItemPoolInterface::class));
        $this->addToAssertionCount(1);
    }

    /**
     * @test
     */
    public function it_rejects_an_unsupported_kind_of_custom_cache(): void
    {
        $this->expectException(InvalidArgumentException::class);
        IdTokenVerifier::createWithProjectIdAndCache('project-id', new stdClass());
    }

    /**
     * @test
     */
    public function it_verifies_a_token(): void
    {
        $this->handler->method('handle')->willReturn($token = $this->createMock(Token::class));

        $this->assertSame($token, $this->verifier->verifyIdToken('token'));
    }

    /**
     * @test
     */
    public function it_verifies_a_token_with_leeway(): void
    {
        $this->handler->method('handle')->willReturn($token = $this->createMock(Token::class));

        $this->assertSame($token, $this->verifier->verifyIdTokenWithLeeway('token', 1337));
    }
}
