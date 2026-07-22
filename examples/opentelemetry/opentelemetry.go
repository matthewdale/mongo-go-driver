// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// This example demonstrates the Go Driver's native OpenTelemetry tracing.
// Passing a TracerProvider to the client makes the driver emit a span for each
// driver operation, with a nested span for each server command the operation
// issues.
package main

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

func newTracerProvider(exp sdktrace.SpanExporter) (*sdktrace.TracerProvider, error) {
	// Ensure default SDK resources and the required service name are set.
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("ExampleService"),
		),
	)
	if err != nil {
		return nil, err
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithResource(r),
	), nil
}

func main() {
	ctx := context.Background()

	exp, err := stdouttrace.New()
	if err != nil {
		log.Fatalf("failed to initialize exporter: %v", err)
	}

	tp, err := newTracerProvider(exp)
	if err != nil {
		log.Fatalf("failed to initialize tracer provider: %v", err)
	}
	defer func() { _ = tp.Shutdown(ctx) }()

	// Pass the TracerProvider to the driver. This is the only configuration
	// tracing requires; when it is not set, the driver records no spans.
	client, err := mongo.Connect(options.Client().
		ApplyURI("mongodb://localhost:27017").
		SetTracingOptions(&options.TracingOptions{
			TracerProvider: tp,
		}))
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = client.Disconnect(ctx) }()

	inventory := client.Database("example").Collection("inventory")

	// Start an application span so the driver's operation span has a parent,
	// showing how driver spans tie into the application's own trace.
	ctx, span := tp.Tracer("example.io/package/name").Start(ctx, "example-request",
		trace.WithSpanKind(trace.SpanKindInternal))

	_, err = inventory.InsertOne(ctx, bson.D{
		{Key: "item", Value: "canvas"},
		{Key: "qty", Value: 100},
		{Key: "attributes", Value: bson.A{"cotton"}},
		{Key: "size", Value: bson.D{
			{Key: "h", Value: 28},
			{Key: "w", Value: 35.5},
			{Key: "uom", Value: "cm"},
		}},
	})

	span.End()

	if err != nil {
		log.Fatalf("failed to insert: %v", err)
	}
}
