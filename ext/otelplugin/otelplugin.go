// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package otelplugin

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"go.mongodb.org/mongo-driver/v2/telemetry"
)

// instrumentationName identifies the spans this module produces.
const instrumentationName = "go.mongodb.org/mongo-driver/ext/otelplugin"

// NewTracer returns a telemetry.Tracer that records the driver's spans with
// OpenTelemetry.
//
// The TracerProvider is resolved when NewTracer is called, not at package
// initialization, so a provider registered with otel.SetTracerProvider in main
// is picked up.
func NewTracer() telemetry.Tracer {
	return &tracer{tracer: otel.GetTracerProvider().Tracer(instrumentationName)}
}

type tracer struct {
	tracer trace.Tracer
}

func (t *tracer) Enabled(context.Context) bool { return true }

func (t *tracer) StartSpan(
	ctx context.Context,
	name string,
	attrs ...telemetry.Attr,
) (context.Context, telemetry.Span) {
	ctx, s := t.tracer.Start(ctx, name, trace.WithAttributes(keyValues(attrs)...))

	return ctx, span{span: s}
}

type span struct {
	span trace.Span
}

func (s span) SetAttributes(attrs ...telemetry.Attr) {
	s.span.SetAttributes(keyValues(attrs)...)
}

func (s span) End(err error) {
	if err != nil {
		s.span.RecordError(err)
		s.span.SetStatus(codes.Error, err.Error())
	}

	s.span.End()
}

// keyValues converts driver attributes to OpenTelemetry attributes. An Attr
// whose Kind is not recognized is skipped: the driver may add Kinds in any
// release, and an unknown one is not an error.
func keyValues(attrs []telemetry.Attr) []attribute.KeyValue {
	if len(attrs) == 0 {
		return nil
	}

	kvs := make([]attribute.KeyValue, 0, len(attrs))

	for _, attr := range attrs {
		switch attr.Kind() {
		case telemetry.KindString:
			kvs = append(kvs, attribute.String(attr.Key(), attr.AsString()))
		case telemetry.KindInt64:
			kvs = append(kvs, attribute.Int64(attr.Key(), attr.AsInt64()))
		case telemetry.KindFloat64:
			kvs = append(kvs, attribute.Float64(attr.Key(), attr.AsFloat64()))
		case telemetry.KindBool:
			kvs = append(kvs, attribute.Bool(attr.Key(), attr.AsBool()))
		case telemetry.KindStringSlice:
			kvs = append(kvs, attribute.StringSlice(attr.Key(), attr.AsStringSlice()))
		case telemetry.KindInt64Slice:
			kvs = append(kvs, attribute.Int64Slice(attr.Key(), attr.AsInt64Slice()))
		case telemetry.KindFloat64Slice:
			kvs = append(kvs, attribute.Float64Slice(attr.Key(), attr.AsFloat64Slice()))
		case telemetry.KindBoolSlice:
			kvs = append(kvs, attribute.BoolSlice(attr.Key(), attr.AsBoolSlice()))
		}
	}

	return kvs
}
