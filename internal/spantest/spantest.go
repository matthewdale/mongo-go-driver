// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package spantest provides a recording OpenTelemetry TracerProvider for tests.
//
// The OpenTelemetry specification forbids drivers from depending on the
// OpenTelemetry SDK, and a test-only import would still be recorded in the
// driver's go.mod. This package therefore implements just enough of the trace
// API to capture what the driver records, using only the API module the driver
// already depends on.
package spantest

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/embedded"
)

// Span is a recorded span.
type Span struct {
	Name       string
	Kind       trace.SpanKind
	Attributes []attribute.KeyValue
	StatusCode codes.Code
	StatusText string
	Errors     []error
	Ended      bool

	// SpanID and ParentSpanID identify the span and its parent. A span with no
	// recorded parent has a zero ParentSpanID.
	SpanID       trace.SpanID
	ParentSpanID trace.SpanID
}

// Attribute returns the value of the named attribute and whether it was set.
func (s *Span) Attribute(key string) (attribute.Value, bool) {
	for _, attr := range s.Attributes {
		if string(attr.Key) == key {
			return attr.Value, true
		}
	}

	return attribute.Value{}, false
}

// HasAttribute reports whether the named attribute was set.
func (s *Span) HasAttribute(key string) bool {
	_, ok := s.Attribute(key)

	return ok
}

// TracerProvider records every span started by the tracers it creates. It is
// safe for concurrent use.
type TracerProvider struct {
	embedded.TracerProvider

	mu     sync.Mutex
	spans  []*Span
	nextID uint64
}

// NewTracerProvider returns a TracerProvider that records spans in memory.
func NewTracerProvider() *TracerProvider {
	return &TracerProvider{}
}

// Tracer implements trace.TracerProvider.
func (tp *TracerProvider) Tracer(string, ...trace.TracerOption) trace.Tracer {
	return &tracer{provider: tp}
}

// Spans returns the spans recorded so far, in the order they were started.
func (tp *TracerProvider) Spans() []*Span {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	return append([]*Span(nil), tp.spans...)
}

// Reset discards all recorded spans.
func (tp *TracerProvider) Reset() {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.spans = nil
}

// Named returns the recorded spans with the given name.
func (tp *TracerProvider) Named(name string) []*Span {
	var out []*Span
	for _, span := range tp.Spans() {
		if span.Name == name {
			out = append(out, span)
		}
	}

	return out
}

// ChildrenOf returns the recorded spans whose parent is the given span.
func (tp *TracerProvider) ChildrenOf(parent *Span) []*Span {
	var out []*Span
	for _, span := range tp.Spans() {
		if span.ParentSpanID == parent.SpanID {
			out = append(out, span)
		}
	}

	return out
}

func (tp *TracerProvider) record(span *Span) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.nextID++
	// SpanIDs must be non-zero and unique so that parent linkage is
	// unambiguous.
	var id trace.SpanID
	for i := 0; i < 8; i++ {
		id[7-i] = byte(tp.nextID >> (8 * i))
	}
	span.SpanID = id
	tp.spans = append(tp.spans, span)
}

type tracer struct {
	embedded.Tracer

	provider *TracerProvider
}

// Start implements trace.Tracer.
func (t *tracer) Start(
	ctx context.Context,
	name string,
	opts ...trace.SpanStartOption,
) (context.Context, trace.Span) {
	cfg := trace.NewSpanStartConfig(opts...)

	recorded := &Span{
		Name:         name,
		Kind:         cfg.SpanKind(),
		Attributes:   cfg.Attributes(),
		ParentSpanID: trace.SpanContextFromContext(ctx).SpanID(),
	}
	t.provider.record(recorded)

	span := &span{recorded: recorded, provider: t.provider}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  recorded.SpanID,
	})
	span.spanContext = sc

	return trace.ContextWithSpan(ctx, span), span
}

// traceID is a fixed, valid trace ID; tests only assert on parent/child
// linkage, which SpanIDs already capture.
var traceID = trace.TraceID{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
}

type span struct {
	embedded.Span

	provider    *TracerProvider
	recorded    *Span
	spanContext trace.SpanContext
}

func (s *span) End(...trace.SpanEndOption) {
	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()

	s.recorded.Ended = true
}

func (s *span) AddEvent(string, ...trace.EventOption) {}

func (s *span) AddLink(trace.Link) {}

func (s *span) IsRecording() bool { return true }

func (s *span) RecordError(err error, _ ...trace.EventOption) {
	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()

	s.recorded.Errors = append(s.recorded.Errors, err)
}

func (s *span) SpanContext() trace.SpanContext { return s.spanContext }

func (s *span) SetStatus(code codes.Code, description string) {
	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()

	s.recorded.StatusCode = code
	s.recorded.StatusText = description
}

func (s *span) SetName(name string) {
	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()

	s.recorded.Name = name
}

func (s *span) SetAttributes(kv ...attribute.KeyValue) {
	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()

	s.recorded.Attributes = append(s.recorded.Attributes, kv...)
}

func (s *span) TracerProvider() trace.TracerProvider { return s.provider }
