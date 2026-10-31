package admission

import (
	"context"
	"errors"
	"tailscale.com/tailcfg"
)

type Verifier interface {
	VerifyClient(context.Context, tailcfg.DERPAdmitClientRequest) error
}

// Chain admits a node only when every check succeeds. One total request quota
// covers both stages; a controller fallback can never bypass a Tailnet denial.
type Chain struct {
	checks   []Verifier
	requests chan struct{}
}

func All(maxRequests int, checks ...Verifier) *Chain {
	if maxRequests <= 0 {
		maxRequests = 128
	}
	maxRequests = min(maxRequests, 8192)
	return &Chain{checks: checks, requests: make(chan struct{}, maxRequests)}
}

func (c *Chain) VerifyClient(ctx context.Context, request tailcfg.DERPAdmitClientRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.requests <- struct{}{}:
		defer func() { <-c.requests }()
	default:
		return ErrLimit
	}
	for _, check := range c.checks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := check.VerifyClient(ctx, request); err != nil {
			return err
		}
	}
	// A controller may explicitly allow its own timeout after the Tailnet check
	// succeeded. Respect that fallback; active cancellation still always denies.
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	return nil
}
