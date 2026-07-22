// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package telemetry

import "context"

// noopTracer and noopSpan are empty structs, so these package-level values are
// free to return and comparing against them is not required anywhere.
var (
	defaultNoopTracer Tracer = noopTracer{}
	defaultNoopSpan   Span   = noopSpan{}
)

// Noop returns a [Tracer] that creates no spans.
//
// The driver substitutes the value returned by Noop wherever no Tracer has been
// configured, so its internal tracer fields are never nil and call sites do not
// need to nil-check before calling [Tracer.Enabled].
func Noop() Tracer { return defaultNoopTracer }

// NoopSpan returns a [Span] that records nothing. Tracer implementations can
// return it from [Tracer.StartSpan] when they decline to record a span.
func NoopSpan() Span { return defaultNoopSpan }

type noopTracer struct{}

func (noopTracer) Enabled(context.Context) bool { return false }

func (noopTracer) StartSpan(ctx context.Context, _ string, _ ...Attr) (context.Context, Span) {
	return ctx, defaultNoopSpan
}

type noopSpan struct{}

func (noopSpan) SetAttributes(...Attr) {}

func (noopSpan) End(error) {}
