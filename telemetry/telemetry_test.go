// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package telemetry

import (
	"context"
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/v2/internal/assert"
)

func TestNoopTracer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tracer := Noop()

	assert.False(t, tracer.Enabled(ctx), "expected the noop tracer to be disabled")

	// The driver does not nil-check the Span returned by StartSpan, so a nil
	// here would be a panic on every operation.
	gotCtx, span := tracer.StartSpan(ctx, "name", String("key", "value"))
	assert.NotNil(t, span, "expected a non-nil Span")
	assert.Equal(t, ctx, gotCtx, "expected the noop tracer to return ctx unchanged")

	// None of these should panic, and End must tolerate being called more than
	// once.
	span.SetAttributes(Int("key", 1))
	span.End(nil)
	span.End(errors.New("err"))
	span.End(nil)
}

func TestNoopSpan(t *testing.T) {
	t.Parallel()

	span := NoopSpan()
	assert.NotNil(t, span, "expected a non-nil Span")

	span.SetAttributes()
	span.End(nil)
}

// TestNoopTracerDoesNotAllocate asserts that the substitute used when no Tracer
// is configured costs nothing beyond the interface call. Combined with the
// Enabled() gate, this is what keeps tracing free for users who do not use it.
// This test cannot call t.Parallel: testing.AllocsPerRun panics if it runs
// concurrently with another test.
func TestNoopTracerDoesNotAllocate(t *testing.T) {
	ctx := context.Background()
	tracer := Noop()

	got := testing.AllocsPerRun(100, func() {
		if tracer.Enabled(ctx) {
			t.Fatal("expected the noop tracer to be disabled")
		}
	})
	assert.Equal(t, float64(0), got, "expected Enabled to allocate 0 times, got %v", got)
}

// recordingTracer is a minimal implementation used to prove the interfaces can
// be satisfied from outside the package without any embedding requirement.
type recordingTracer struct {
	started []string
}

func (rt *recordingTracer) Enabled(context.Context) bool { return true }

func (rt *recordingTracer) StartSpan(
	ctx context.Context,
	name string,
	_ ...Attr,
) (context.Context, Span) {
	rt.started = append(rt.started, name)

	return ctx, NoopSpan()
}

var (
	_ Tracer = &recordingTracer{}
	_ Tracer = Noop()
	_ Span   = NoopSpan()
)

func TestTracerIsImplementableExternally(t *testing.T) {
	t.Parallel()

	rt := &recordingTracer{}

	_, span := rt.StartSpan(context.Background(), "insert")
	span.End(nil)

	assert.Equal(t, []string{"insert"}, rt.started)
}
