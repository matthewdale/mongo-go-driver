// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package observability

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"
	"go.mongodb.org/mongo-driver/v2/internal/assert"
	"go.mongodb.org/mongo-driver/v2/internal/logger"
	"go.mongodb.org/mongo-driver/v2/internal/spantest"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func startedInfo() CommandStartedInfo {
	serverConnID := int64(42)

	return CommandStartedInfo{
		Command:            bson.Raw{},
		CommandName:        "insert",
		DatabaseName:       "testdb",
		CollectionName:     "testcoll",
		RequestID:          7,
		ConnectionID:       "localhost:27017[-1]",
		DriverConnectionID: 3,
		ServerConnectionID: &serverConnID,
		ServerAddress:      "localhost:27017",
		NetworkTransport:   TransportTCP,
		LSID:               "5f1b0d2a-0000-0000-0000-000000000000",
	}
}

// TestZeroObserverIsSafe verifies that an Observer with no sinks configured
// discards everything without panicking. This is the path every application
// that has not enabled monitoring, logging, or tracing takes.
func TestZeroObserverIsSafe(t *testing.T) {
	t.Parallel()

	var obs Observer

	ctx, span := obs.OperationStarted(context.Background(), OperationInfo{
		Name:           "insert",
		DatabaseName:   "testdb",
		CollectionName: "testcoll",
	})
	assert.NotNil(t, span, "expected a non-nil span")
	span.End()

	ctx, cmdSpan := obs.CommandStarted(ctx, startedInfo())
	assert.NotNil(t, cmdSpan, "expected a non-nil command span")

	obs.CommandFinished(ctx, cmdSpan, CommandFinishedInfo{
		CommandStartedInfo: startedInfo(),
		Duration:           time.Millisecond,
		Success:            true,
	})
}

// TestNilSinksIndependentlySafe verifies that each sink can be configured
// without the others.
func TestNilSinksIndependentlySafe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		obs  Observer
	}{
		{
			name: "tracer only",
			obs:  Observer{Tracer: spantest.NewTracerProvider().Tracer("")},
		},
		{
			name: "monitor only",
			obs:  Observer{CommandMonitor: &event.CommandMonitor{}},
		},
		{
			name: "logger only",
			obs:  Observer{Logger: &logger.Logger{}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, span := test.obs.CommandStarted(context.Background(), startedInfo())
			test.obs.CommandFinished(ctx, span, CommandFinishedInfo{
				CommandStartedInfo: startedInfo(),
				Duration:           time.Millisecond,
				Success:            true,
			})
		})
	}
}

// TestOperationSpan verifies the operation span's name and attributes.
func TestOperationSpan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		info     OperationInfo
		wantName string
		wantColl bool
	}{
		{
			name: "collection operation",
			info: OperationInfo{
				Name:           "insert",
				DatabaseName:   "testdb",
				CollectionName: "testcoll",
			},
			wantName: "insert testdb.testcoll",
			wantColl: true,
		},
		{
			// The spec omits db.collection.name for operations that do not
			// target a collection, and names the span "<operation> <db>".
			name: "database operation",
			info: OperationInfo{
				Name:         "runCommand",
				DatabaseName: "admin",
			},
			wantName: "runCommand admin",
			wantColl: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			tp := spantest.NewTracerProvider()
			obs := Observer{Tracer: tp.Tracer("")}

			_, span := obs.OperationStarted(context.Background(), test.info)
			span.End()

			spans := tp.Spans()
			assert.Len(t, spans, 1, "expected exactly one span")

			got := spans[0]
			assert.Equal(t, test.wantName, got.Name, "span name")
			assert.Equal(t, trace.SpanKindClient, got.Kind, "span kind")
			assert.True(t, got.Ended, "expected the span to be ended")

			systemName, ok := got.Attribute("db.system.name")
			assert.True(t, ok, "expected db.system.name")
			assert.Equal(t, "mongodb", systemName.AsString(), "db.system.name")

			namespace, ok := got.Attribute("db.namespace")
			assert.True(t, ok, "expected db.namespace")
			assert.Equal(t, test.info.DatabaseName, namespace.AsString(), "db.namespace")

			opName, ok := got.Attribute("db.operation.name")
			assert.True(t, ok, "expected db.operation.name")
			assert.Equal(t, test.info.Name, opName.AsString(), "db.operation.name")

			// db.operation.summary is required to equal the span name.
			summary, ok := got.Attribute("db.operation.summary")
			assert.True(t, ok, "expected db.operation.summary")
			assert.Equal(t, test.wantName, summary.AsString(), "db.operation.summary")

			assert.Equal(t, test.wantColl, got.HasAttribute("db.collection.name"),
				"db.collection.name presence")
		})
	}
}

// TestCommandSpanAttributes verifies the command span's name and the attributes
// the OpenTelemetry specification requires.
func TestCommandSpanAttributes(t *testing.T) {
	t.Parallel()

	tp := spantest.NewTracerProvider()
	obs := Observer{Tracer: tp.Tracer("")}

	_, span := obs.CommandStarted(context.Background(), startedInfo())
	span.End()

	spans := tp.Spans()
	assert.Len(t, spans, 1, "expected exactly one span")

	got := spans[0]
	assert.Equal(t, "insert", got.Name, "span name is the command name")
	assert.Equal(t, trace.SpanKindClient, got.Kind, "span kind")

	want := map[string]any{
		"db.system.name":                  "mongodb",
		"db.namespace":                    "testdb",
		"db.collection.name":              "testcoll",
		"db.command.name":                 "insert",
		"db.query.summary":                "insert testdb.testcoll",
		"server.address":                  "localhost",
		"server.port":                     int64(27017),
		"network.transport":               "tcp",
		"db.mongodb.server_connection_id": int64(42),
		"db.mongodb.driver_connection_id": int64(3),
		"db.mongodb.lsid":                 "5f1b0d2a-0000-0000-0000-000000000000",
	}

	for key, wantVal := range want {
		val, ok := got.Attribute(key)
		if !assert.True(t, ok, "expected attribute %q", key) {
			continue
		}

		switch expected := wantVal.(type) {
		case string:
			assert.Equal(t, expected, val.AsString(), "attribute %q", key)
		case int64:
			assert.Equal(t, expected, val.AsInt64(), "attribute %q", key)
		}
	}

	// txn_number is only set inside a transaction.
	assert.False(t, got.HasAttribute("db.mongodb.txn_number"),
		"db.mongodb.txn_number should be omitted outside a transaction")
}

// TestSensitiveCommandIsNotTraced verifies that security sensitive commands
// produce no span, as the specification requires, while still producing the
// event and log message that command monitoring expects.
func TestSensitiveCommandIsNotTraced(t *testing.T) {
	t.Parallel()

	tp := spantest.NewTracerProvider()

	var started int
	obs := Observer{
		Tracer: tp.Tracer(""),
		CommandMonitor: &event.CommandMonitor{
			Started: func(context.Context, *event.CommandStartedEvent) { started++ },
		},
	}

	info := startedInfo()
	info.CommandName = "saslStart"
	info.Sensitive = true
	info.Command = nil

	_, span := obs.CommandStarted(context.Background(), info)
	span.End()

	assert.Len(t, tp.Spans(), 0, "expected no spans for a sensitive command")
	assert.Equal(t, 1, started, "expected the started event to still be published")
}

// TestSensitiveCommandDoesNotEndParentSpan guards against the sensitive-command
// path returning the parent span, which would let the caller's End close the
// operation span early.
func TestSensitiveCommandDoesNotEndParentSpan(t *testing.T) {
	t.Parallel()

	tp := spantest.NewTracerProvider()
	obs := Observer{Tracer: tp.Tracer("")}

	ctx, opSpan := obs.OperationStarted(context.Background(), OperationInfo{
		Name:         "saslStart",
		DatabaseName: "admin",
	})

	info := startedInfo()
	info.Sensitive = true

	_, cmdSpan := obs.CommandStarted(ctx, info)
	cmdSpan.End()

	spans := tp.Spans()
	assert.Len(t, spans, 1, "expected only the operation span")
	assert.False(t, spans[0].Ended, "the operation span must not have been ended")

	opSpan.End()
	assert.True(t, spans[0].Ended, "the operation span should end when its owner ends it")
}

// TestCommandFinishedRecordsError verifies that a failed command records an
// exception and the MongoDB error code on the command span.
func TestCommandFinishedRecordsError(t *testing.T) {
	t.Parallel()

	tp := spantest.NewTracerProvider()
	obs := Observer{Tracer: tp.Tracer("")}

	ctx, span := obs.CommandStarted(context.Background(), startedInfo())

	cmdErr := errors.New("command failed")
	obs.CommandFinished(ctx, span, CommandFinishedInfo{
		CommandStartedInfo: startedInfo(),
		Duration:           time.Millisecond,
		Err:                cmdErr,
		StatusCode:         "11602",
		Success:            false,
	})

	spans := tp.Spans()
	assert.Len(t, spans, 1, "expected exactly one span")

	got := spans[0]
	assert.True(t, got.Ended, "expected the span to be ended")
	assert.Equal(t, codes.Error, got.StatusCode, "span status")
	assert.Len(t, got.Errors, 1, "expected one recorded error")
	assert.ErrorIs(t, got.Errors[0], cmdErr, "recorded error")

	statusCode, ok := got.Attribute("db.response.status_code")
	assert.True(t, ok, "expected db.response.status_code")
	assert.Equal(t, "11602", statusCode.AsString(), "db.response.status_code")
}

// TestCommandFinishedSuccessRecordsNoError verifies that a successful command
// leaves the span unset, and in particular that a command which returned write
// errors is still a success: the command ran, only the writes failed.
func TestCommandFinishedSuccessRecordsNoError(t *testing.T) {
	t.Parallel()

	tp := spantest.NewTracerProvider()
	obs := Observer{Tracer: tp.Tracer("")}

	ctx, span := obs.CommandStarted(context.Background(), startedInfo())
	obs.CommandFinished(ctx, span, CommandFinishedInfo{
		CommandStartedInfo: startedInfo(),
		Duration:           time.Millisecond,
		Err:                errors.New("write errors"),
		Success:            true,
	})

	spans := tp.Spans()
	assert.Len(t, spans, 1, "expected exactly one span")
	assert.Len(t, spans[0].Errors, 0, "a successful command must record no exception")
	assert.Equal(t, codes.Unset, spans[0].StatusCode, "span status should be unset")
}

// TestCommandSpanNestsUnderOperationSpan verifies the parent/child relationship
// the specification requires between operation and command spans.
func TestCommandSpanNestsUnderOperationSpan(t *testing.T) {
	t.Parallel()

	tp := spantest.NewTracerProvider()
	obs := Observer{Tracer: tp.Tracer("")}

	ctx, opSpan := obs.OperationStarted(context.Background(), OperationInfo{
		Name:           "insert",
		DatabaseName:   "testdb",
		CollectionName: "testcoll",
	})

	// Two attempts, as a retry would produce. Both are started from the same
	// context, so both are children of the operation span rather than of each
	// other.
	for i := 0; i < 2; i++ {
		_, span := obs.CommandStarted(ctx, startedInfo())
		obs.CommandFinished(ctx, span, CommandFinishedInfo{
			CommandStartedInfo: startedInfo(),
			Success:            true,
		})
	}
	opSpan.End()

	operations := tp.Named("insert testdb.testcoll")
	assert.Len(t, operations, 1, "expected one operation span")

	children := tp.ChildrenOf(operations[0])
	assert.Len(t, children, 2, "expected both command spans to be children of the operation span")
	for _, child := range children {
		assert.Equal(t, "insert", child.Name, "command span name")
		assert.True(t, child.Ended, "expected the command span to be ended")
	}
}

// TestNetworkTransportUnix verifies the unix transport attribute.
func TestNetworkTransportUnix(t *testing.T) {
	t.Parallel()

	tp := spantest.NewTracerProvider()
	obs := Observer{Tracer: tp.Tracer("")}

	info := startedInfo()
	info.ServerAddress = "/tmp/mongodb-27017.sock"
	info.NetworkTransport = TransportUnix

	_, span := obs.CommandStarted(context.Background(), info)
	span.End()

	spans := tp.Spans()
	assert.Len(t, spans, 1, "expected exactly one span")

	transport, ok := spans[0].Attribute("network.transport")
	assert.True(t, ok, "expected network.transport")
	assert.Equal(t, "unix", transport.AsString(), "network.transport")

	// A Unix socket path has no port, so server.port must be omitted.
	assert.False(t, spans[0].HasAttribute("server.port"), "server.port should be omitted")
}
