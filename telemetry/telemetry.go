// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package telemetry

import "context"

// Tracer creates spans describing the work the driver performs on behalf of an
// operation. Register a Tracer with
// [go.mongodb.org/mongo-driver/v2/mongo/options.ClientOptions.SetTracer].
//
// A Tracer must be safe for concurrent use by multiple goroutines.
//
// Methods may be added to Tracer in any release. See the package documentation
// for the stability policy.
type Tracer interface {
	// Enabled reports whether the driver should create spans for ctx.
	//
	// The driver calls Enabled before building any attributes, so an
	// implementation that returns false lets the driver skip that work
	// entirely. Enabled is called at least once per operation and must not
	// block or allocate. Returning true unconditionally is always correct.
	Enabled(ctx context.Context) bool

	// StartSpan starts a span named name and returns a context carrying it
	// along with the Span itself. The driver uses the returned context for all
	// work that logically happens inside the span, so spans started with it
	// become children of this one.
	//
	// StartSpan must never return a nil Span. An implementation that declines
	// to record a span must return a no-op Span, such as the one returned by
	// [NoopSpan]; the driver does not nil-check the result.
	StartSpan(ctx context.Context, name string, attrs ...Attr) (context.Context, Span)
}

// Span is a single traced unit of work.
//
// A Span must be safe for concurrent use by multiple goroutines.
//
// Methods may be added to Span in any release. See the package documentation
// for the stability policy.
type Span interface {
	// SetAttributes adds attributes to the span, overwriting any existing
	// attribute with the same key. The driver calls SetAttributes for values
	// that are not known when the span starts, such as the address of the
	// server that was ultimately selected.
	//
	// SetAttributes must ignore an Attr whose Kind it does not recognize.
	SetAttributes(attrs ...Attr)

	// End completes the span. If err is non-nil, the span should be marked as
	// failed and err recorded on it.
	//
	// End must be idempotent. The driver makes a best effort to call End
	// exactly once per span, but some code paths -- notably the retry loop,
	// where a span may be ended either at the top of the next iteration or by a
	// deferred call when the operation returns -- rely on a repeated End being
	// harmless.
	End(err error)
}
