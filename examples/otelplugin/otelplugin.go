// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/ext/otelplugin"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.42.0"
)

func newTracerProvider(exp sdktrace.SpanExporter) *sdktrace.TracerProvider {
	// Ensure default SDK resources and the required service name are set.
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("ExampleService"),
		),
	)
	if err != nil {
		panic(err)
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	)
}

func main() {
	ctx := context.Background()

	exp, err := stdouttrace.New()
	if err != nil {
		log.Fatalf("failed to initialize exporter: %v", err)
	}
	defer exp.Shutdown(context.Background())

	// Create a new tracer provider with a batch span processor and the given exporter.
	tp := newTracerProvider(exp)

	// Handle shutdown properly so nothing leaks.
	defer func() { _ = tp.Shutdown(ctx) }()

	otel.SetTracerProvider(tp)

	client, err := mongo.Connect(options.Client().
		ApplyURI("mongodb://localhost:27017").
		SetTracer(otelplugin.NewTracer()))
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()
	inventory := client.Database("example").Collection("inventory")

	// Finally, set the tracer that can be used for this package.
	tracer := tp.Tracer("example.io/package/name")

	// Insert a fixed number of documents rather than looping forever, so that
	// the batched spans are flushed by the deferred provider shutdown and the
	// example terminates on its own.
	for i := 0; i < 3; i++ {
		log.Println("Inserting document...")

		ctx, span := tracer.Start(ctx, "hello-span")
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
		if err != nil {
			panic(err)
		}
		span.End()
	}
}
