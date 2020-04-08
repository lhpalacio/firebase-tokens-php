<?php

declare(strict_types=1);

namespace Kreait\Firebase\JWT\Tests;

use Kreait\Firebase\JWT\Action\CreateCustomToken\Handler;
use Kreait\Firebase\JWT\Contract\Token;
use Kreait\Firebase\JWT\CustomTokenGenerator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class CustomTokenGeneratorTest extends TestCase
{
    /** @var Handler|MockObject */
    private $handler;

    /** @var CustomTokenGenerator */
    private $generator;

    protected function setUp(): void
    {
        $this->handler = $this->createMock(Handler::class);

        $this->generator = new CustomTokenGenerator($this->handler);
    }

    /**
     * @test
     */
    public function it_can_be_created_with_credentials(): void
    {
        CustomTokenGenerator::withClientEmailAndPrivateKey('email@domain.tld', 'some-private-key');
        $this->addToAssertionCount(1);
    }

    /**
     * @test
     */
    public function it_creates_a_custom_token_for_an_uid_only(): void
    {
        $this->handler->method('handle')->willReturn($token = $this->createMock(Token::class));

        $this->assertSame($token, $this->generator->createCustomToken('uid'));
    }

    /**
     * @test
     */
    public function it_creates_a_custom_token_for_an_uid_with_custom_claims(): void
    {
        $this->handler->method('handle')->willReturn($token = $this->createMock(Token::class));

        $this->assertSame($token, $this->generator->createCustomToken('uid', ['custom' => 'claim']));
    }

    /**
     * @test
     */
    public function it_creates_a_custom_token_with_a_custom_ttl(): void
    {
        $this->handler->method('handle')->willReturn($token = $this->createMock(Token::class));

        $this->assertSame($token, $this->generator->createCustomToken('uid', [], 1337));
    }
}
