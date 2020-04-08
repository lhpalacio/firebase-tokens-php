<?php

declare(strict_types=1);

namespace Kreait\Firebase\JWT\Action;

use DateInterval;
use InvalidArgumentException;
use Kreait\Firebase\JWT\Value\Duration;

final class CreateCustomToken
{
    private const MINIMUM_TTL = 'PT1S';
    private const MAXIMUM_TTL = 'PT1H';
    private const DEFAULT_TTL = self::MAXIMUM_TTL;

    /** @var string */
    private $uid;

    /** @var array<string, mixed> */
    private $customClaims = [];

    /** @var Duration */
    private $ttl;

    private function __construct()
    {
        $this->ttl = Duration::fromDateIntervalSpec(self::DEFAULT_TTL);
    }

    public static function forUid(string $uid): self
    {
        $action = new self();
        $action->uid = $uid;

        return $action;
    }

    public function withChangedUid(string $uid): self
    {
        $action = clone $this;
        $action->uid = $uid;

        return $action;
    }

    /**
     * @param mixed $value
     */
    public function withCustomClaim(string $name, $value): self
    {
        $action = clone $this;
        $action->customClaims[$name] = $value;

        return $action;
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function withCustomClaims(array $claims): self
    {
        $action = clone $this;
        $action->customClaims = $claims;

        return $action;
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function withAddedCustomClaims(array $claims): self
    {
        $action = clone $this;
        $action->customClaims = array_merge($action->customClaims, $claims);

        return $action;
    }

    /**
     * @param self|DateInterval|int|string|mixed $ttl
     *
     * @throws InvalidArgumentException
     */
    public function withTimeToLive($ttl): self
    {
        $ttl = Duration::make($ttl);

        $minTtl = Duration::fromDateIntervalSpec(self::MINIMUM_TTL);
        $maxTtl = Duration::fromDateIntervalSpec(self::MAXIMUM_TTL);

        if ($ttl->isSmallerThan($minTtl) || $ttl->isLargerThan($maxTtl)) {
            $message = 'The expiration time of a custom token must be between %s and %s, but got %s';
            throw new InvalidArgumentException(sprintf($message, $minTtl, $maxTtl, $ttl));
        }

        $action = clone $this;
        $action->ttl = $ttl;

        return $action;
    }

    public function uid(): string
    {
        return $this->uid;
    }

    /**
     * @return array<string, mixed>
     */
    public function customClaims(): array
    {
        return $this->customClaims;
    }

    public function timeToLive(): Duration
    {
        return $this->ttl;
    }
}
