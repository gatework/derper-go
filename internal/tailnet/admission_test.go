package tailnet

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/types/key"
)

func TestAdmissionBoundsAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		v := New(Options{MaxConcurrentChecks: 4})
		defer v.Close()
		v.lookup = func(ctx context.Context, _ key.NodePublic) error { <-ctx.Done(); return ctx.Err() }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		results := make(chan error, maxAdmissionRequests)
		for range maxAdmissionRequests {
			go func() { results <- v.VerifyNode(ctx, key.NewNode().Public()) }()
		}
		synctest.Wait()
		if s := v.Stats(); s.Requests != maxAdmissionRequests || s.Running != 4 || s.PeakRunning != 4 {
			t.Fatal(s)
		}
		if err := v.VerifyNode(ctx, key.NewNode().Public()); !errors.Is(err, ErrAdmissionLimit) {
			t.Fatal(err)
		}
		cancel()
		for range maxAdmissionRequests {
			if err := <-results; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		}
		v.Close()
		if s := v.Stats(); s.Requests != 0 || s.Running != 0 || s.Limited != 1 {
			t.Fatal("resources retained", s)
		}
		if err := v.VerifyNode(context.Background(), key.NewNode().Public()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	})
}

func TestSameNodeSharesOnlyInflightLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		v := New(Options{})
		defer v.Close()
		release := make(chan struct{})
		var calls atomic.Int32
		v.lookup = func(ctx context.Context, _ key.NodePublic) error {
			if calls.Add(1) > 1 {
				return ErrUnauthorized
			}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		node := key.NewNode().Public()
		ctx, cancel := context.WithCancel(context.Background())
		first := make(chan error, 1)
		go func() { first <- v.VerifyNode(ctx, node) }()
		synctest.Wait()
		rest := make(chan error, 15)
		for range 15 {
			go func() { rest <- v.VerifyNode(context.Background(), node) }()
		}
		synctest.Wait()
		cancel()
		if err := <-first; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if calls.Load() != 1 || v.Stats().Coalesced != 15 {
			t.Fatal("lookup not coalesced", calls.Load(), v.Stats())
		}
		close(release)
		for range 15 {
			if err := <-rest; err != nil {
				t.Fatal("one caller canceled shared lookup", err)
			}
		}
		if err := v.VerifyNode(context.Background(), node); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("completed authorization was cached", err)
		}
		if calls.Load() != 2 {
			t.Fatal(calls.Load())
		}
	})
}

func TestQueueAndLookupShareOneDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		v := New(Options{MaxConcurrentChecks: 1})
		defer v.Close()
		v.lookup = func(ctx context.Context, _ key.NodePublic) error { <-ctx.Done(); return ctx.Err() }
		results := make(chan error, 2)
		for range 2 {
			go func() { results <- v.VerifyNode(context.Background(), key.NewNode().Public()) }()
		}
		synctest.Wait()
		time.Sleep(admissionTimeout)
		synctest.Wait()
		for range 2 {
			if err := <-results; !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		}
		if s := v.Stats(); s.Running != 0 || s.Requests != 0 {
			t.Fatal(s)
		}
	})
}

func TestCloseJoinsPendingLookups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		v := New(Options{})
		v.lookup = func(ctx context.Context, _ key.NodePublic) error { <-ctx.Done(); return ctx.Err() }
		done := make(chan error, 1)
		go func() { done <- v.VerifyNode(context.Background(), key.NewNode().Public()) }()
		synctest.Wait()
		v.Close()
		if err := <-done; !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if v.Stats().Running != 0 {
			t.Fatal("lookup leaked")
		}
	})
}
