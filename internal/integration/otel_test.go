// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package integration

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/internal/assert"
	"go.mongodb.org/mongo-driver/v2/internal/failpoint"
	"go.mongodb.org/mongo-driver/v2/internal/integration/mtest"
	"go.mongodb.org/mongo-driver/v2/internal/spantest"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// attrString returns the string value of a span attribute, failing the test if
// the attribute is not set.
func attrString(mt *mtest.T, span *spantest.Span, key string) string {
	mt.Helper()

	val, ok := span.Attribute(key)
	assert.True(mt, ok, "expected attribute %q on span %q", key, span.Name)

	return val.AsString()
}

// TestOtelInsert verifies the spans the OpenTelemetry specification requires for
// the insert operation.
func TestOtelInsert(t *testing.T) {
	tp := spantest.NewTracerProvider()

	mtOpts := mtest.NewOptions().
		CreateClient(true).
		ClientOptions(options.Client().SetTracerProvider(tp))

	mt := mtest.New(t, mtOpts)

	mt.Run("operation span with nested command span", func(mt *mtest.T) {
		tp.Reset()

		_, err := mt.Coll.InsertOne(context.Background(), bson.D{{"x", 1}})
		assert.NoError(mt, err, "InsertOne error")

		wantOpName := "insert " + mt.DB.Name() + "." + mt.Coll.Name()

		operations := tp.Named(wantOpName)
		assert.Len(mt, operations, 1, "expected exactly one operation span named %q", wantOpName)

		op := operations[0]
		assert.Equal(mt, trace.SpanKindClient, op.Kind, "operation span kind")
		assert.True(mt, op.Ended, "expected the operation span to be ended")
		assert.Equal(mt, "mongodb", attrString(mt, op, "db.system.name"), "db.system.name")
		assert.Equal(mt, mt.DB.Name(), attrString(mt, op, "db.namespace"), "db.namespace")
		assert.Equal(mt, mt.Coll.Name(), attrString(mt, op, "db.collection.name"), "db.collection.name")
		assert.Equal(mt, "insert", attrString(mt, op, "db.operation.name"), "db.operation.name")
		assert.Equal(mt, wantOpName, attrString(mt, op, "db.operation.summary"), "db.operation.summary")
		assert.Len(mt, op.Errors, 0, "expected no recorded errors on the operation span")

		commands := tp.ChildrenOf(op)
		assert.Len(mt, commands, 1, "expected exactly one command span under the operation span")

		cmd := commands[0]
		assert.Equal(mt, "insert", cmd.Name, "command span name")
		assert.Equal(mt, trace.SpanKindClient, cmd.Kind, "command span kind")
		assert.True(mt, cmd.Ended, "expected the command span to be ended")
		assert.Equal(mt, "mongodb", attrString(mt, cmd, "db.system.name"), "db.system.name")
		assert.Equal(mt, mt.DB.Name(), attrString(mt, cmd, "db.namespace"), "db.namespace")
		assert.Equal(mt, mt.Coll.Name(), attrString(mt, cmd, "db.collection.name"), "db.collection.name")
		assert.Equal(mt, "insert", attrString(mt, cmd, "db.command.name"), "db.command.name")
		assert.Equal(mt, "insert "+mt.DB.Name()+"."+mt.Coll.Name(),
			attrString(mt, cmd, "db.query.summary"), "db.query.summary")

		// Connection and server identity must be present for the span to be
		// useful in debugging.
		for _, key := range []string{
			"server.address",
			"server.port",
			"network.transport",
			"db.mongodb.driver_connection_id",
			"db.mongodb.server_connection_id",
			"db.mongodb.lsid",
		} {
			assert.True(mt, cmd.HasAttribute(key), "expected attribute %q on the command span", key)
		}

		// db.query.text is not implemented yet and must not appear by default.
		assert.False(mt, cmd.HasAttribute("db.query.text"),
			"db.query.text must not be set by default")
	})

	mt.Run("operation span parents the application span", func(mt *mtest.T) {
		tp.Reset()

		ctx, appSpan := tp.Tracer("").Start(context.Background(), "application")
		_, err := mt.Coll.InsertOne(ctx, bson.D{{"x", 1}})
		assert.NoError(mt, err, "InsertOne error")
		appSpan.End()

		apps := tp.Named("application")
		assert.Len(mt, apps, 1, "expected one application span")

		children := tp.ChildrenOf(apps[0])
		assert.Len(mt, children, 1, "expected the operation span to be a child of the application span")
		assert.Equal(mt, "insert "+mt.DB.Name()+"."+mt.Coll.Name(), children[0].Name,
			"operation span name")
	})

	mt.RunOpts("retry produces sibling command spans", mtest.NewOptions().
		MinServerVersion("4.0").Topologies(mtest.ReplicaSet), func(mt *mtest.T) {
		tp.Reset()

		mt.SetFailPoint(failpoint.FailPoint{
			ConfigureFailPoint: "failCommand",
			Mode:               failpoint.Mode{Times: 1},
			Data: failpoint.Data{
				FailCommands: []string{"insert"},
				ErrorCode:    11602, // InterruptedDueToReplStateChange
				ErrorLabels:  &[]string{"RetryableWriteError"},
			},
		})

		_, err := mt.Coll.InsertOne(context.Background(), bson.D{{"x", 1}})
		assert.NoError(mt, err, "InsertOne error")

		wantOpName := "insert " + mt.DB.Name() + "." + mt.Coll.Name()
		operations := tp.Named(wantOpName)
		assert.Len(mt, operations, 1, "a retried operation must still produce exactly one operation span")

		// Both the failed attempt and the retry must be children of the single
		// operation span, not nested inside one another.
		commands := tp.ChildrenOf(operations[0])
		assert.Len(mt, commands, 2, "expected one command span per attempt")

		assert.Len(mt, commands[0].Errors, 1, "the failed attempt must record an exception")
		assert.Equal(mt, codes.Error, commands[0].StatusCode, "failed attempt span status")
		assert.Equal(mt, "11602", attrString(mt, commands[0], "db.response.status_code"),
			"db.response.status_code")

		assert.Len(mt, commands[1].Errors, 0, "the successful retry must record no exception")
	})

	mt.Run("batch split produces one command span per batch", func(mt *mtest.T) {
		tp.Reset()

		// Exceed the server's maxWriteBatchSize (100,000) so the insert is split
		// across more than one command.
		docs := make([]any, 100_001)
		for i := range docs {
			docs[i] = bson.D{{"x", i}}
		}

		_, err := mt.Coll.InsertMany(context.Background(), docs)
		assert.NoError(mt, err, "InsertMany error")

		wantOpName := "insert " + mt.DB.Name() + "." + mt.Coll.Name()
		operations := tp.Named(wantOpName)
		assert.Len(mt, operations, 1, "a split insert must still produce exactly one operation span")

		commands := tp.ChildrenOf(operations[0])
		assert.True(mt, len(commands) > 1,
			"expected more than one command span for a split batch, got %d", len(commands))
		for _, cmd := range commands {
			assert.Equal(mt, "insert", cmd.Name, "command span name")
			assert.True(mt, cmd.Ended, "expected the command span to be ended")
		}
	})

	// This change traces only the insert operation. Command spans are created in
	// the shared operation execution path, but they are only recorded for
	// operations whose tracer has been plumbed through, so other operations stay
	// untraced until they are instrumented in turn.
	mt.Run("other operations are not traced yet", func(mt *mtest.T) {
		tp.Reset()

		_, err := mt.Coll.Find(context.Background(), bson.D{})
		assert.NoError(mt, err, "Find error")

		assert.Len(mt, tp.Spans(), 0, "expected no spans for an uninstrumented operation")

		// BulkWrite issues insert commands through the same operation struct,
		// but it has no operation span of its own yet. It must stay untraced
		// rather than emit command spans with no parent.
		tp.Reset()

		_, err = mt.Coll.BulkWrite(context.Background(),
			[]mongo.WriteModel{mongo.NewInsertOneModel().SetDocument(bson.D{{"x", 1}})})
		assert.NoError(mt, err, "BulkWrite error")

		assert.Len(mt, tp.Spans(), 0, "expected no orphaned command spans from BulkWrite")
	})

	mt.Run("write error records an exception on the operation span only", func(mt *mtest.T) {
		tp.Reset()

		doc := bson.D{{"_id", 1}}
		_, err := mt.Coll.InsertOne(context.Background(), doc)
		assert.NoError(mt, err, "first InsertOne error")

		tp.Reset()

		// A duplicate key is a write error: the insert command itself ran, so
		// per command monitoring semantics the command succeeded.
		_, err = mt.Coll.InsertOne(context.Background(), doc)
		assert.Error(mt, err, "expected a duplicate key error")

		wantOpName := "insert " + mt.DB.Name() + "." + mt.Coll.Name()
		operations := tp.Named(wantOpName)
		assert.Len(mt, operations, 1, "expected one operation span")
		assert.Len(mt, operations[0].Errors, 1,
			"the operation span must record the exception the user sees")

		commands := tp.ChildrenOf(operations[0])
		assert.Len(mt, commands, 1, "expected one command span")
		assert.Len(mt, commands[0].Errors, 0,
			"a write error is a successful command and must not record an exception")
	})
}

// TestOtelDisabled verifies that the driver records nothing when no
// TracerProvider is configured, which is the default.
func TestOtelDisabled(t *testing.T) {
	tp := spantest.NewTracerProvider()

	mt := mtest.New(t, mtest.NewOptions().CreateClient(true))

	mt.Run("no spans without a TracerProvider", func(mt *mtest.T) {
		_, err := mt.Coll.InsertOne(context.Background(), bson.D{{"x", 1}})
		assert.NoError(mt, err, "InsertOne error")

		assert.Len(mt, tp.Spans(), 0, "expected no spans when tracing is not configured")
	})
}
