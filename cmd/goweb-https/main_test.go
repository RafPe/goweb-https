package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// blockUntilDone is a component that runs until its context is cancelled.
func blockUntilDone(started *atomic.Bool) func(context.Context) error {
	return func(ctx context.Context) error {
		started.Store(true)
		<-ctx.Done()
		return nil
	}
}

func TestRunComponents_StopsAllOnCancellation(t *testing.T) {
	t.Parallel()

	var first, second atomic.Bool

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runComponents(ctx, blockUntilDone(&first), blockUntilDone(&second)) }()

	waitFor(t, func() bool { return first.Load() && second.Load() }, "both components to start")
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runComponents = %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runComponents did not return after cancellation")
	}
}

// TestRunComponents_FirstFailureBringsDownTheRest is the behaviour that decides
// whether the orchestrator restarts the pod: a terminally failed certificate
// watcher must stop the server and surface its error, not leave a pod serving
// happily while rotation has silently stopped being observed.
func TestRunComponents_FirstFailureBringsDownTheRest(t *testing.T) {
	t.Parallel()

	watcherFailure := errors.New("filesystem watcher closed")

	var serverStopped atomic.Bool
	server := func(ctx context.Context) error {
		<-ctx.Done()
		serverStopped.Store(true)
		return nil
	}
	watcher := func(context.Context) error { return watcherFailure }

	err := runComponents(t.Context(), server, watcher)

	if !errors.Is(err, watcherFailure) {
		t.Errorf("error = %v, want one matching %v", err, watcherFailure)
	}
	if !serverStopped.Load() {
		t.Error("the server was not cancelled when the watcher failed")
	}
}

func TestRunComponents_JoinsMultipleFailures(t *testing.T) {
	t.Parallel()

	first := errors.New("server failed")
	second := errors.New("watcher failed")

	err := runComponents(t.Context(),
		func(context.Context) error { return first },
		func(ctx context.Context) error {
			// Wait for the cancellation triggered by the other failure so both
			// errors are produced in the same run.
			<-ctx.Done()
			return second
		},
	)

	for _, want := range []error{first, second} {
		if !errors.Is(err, want) {
			t.Errorf("error %v does not wrap %v", err, want)
		}
	}
}

func waitFor(t *testing.T, condition func() bool, describe string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", describe)
}
