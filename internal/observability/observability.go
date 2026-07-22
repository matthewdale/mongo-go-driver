// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package observability fans a single lifecycle moment out to every configured
// observability sink: command monitor events, structured log messages, and
// OpenTelemetry spans.
//
// The driver has historically emitted events and log messages from separate,
// hand-written call sites, so the same payload was assembled twice and the two
// vocabularies drifted apart. Adding tracing as a third mechanism would
// compound that, so each lifecycle moment is instead described once here and
// dispatched to whichever sinks the user configured.
package observability

import (
	"context"
	"net"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"
	"go.mongodb.org/mongo-driver/v2/internal/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Attribute keys required by the OpenTelemetry specification that have no
// semconv equivalent at the schema version the driver targets.
const (
	dbOperationSummaryKey = attribute.Key("db.operation.summary")
	dbCommandNameKey      = attribute.Key("db.command.name")
	serverConnectionIDKey = attribute.Key("db.mongodb.server_connection_id")
	driverConnectionIDKey = attribute.Key("db.mongodb.driver_connection_id")
	lsidKey               = attribute.Key("db.mongodb.lsid")
	txnNumberKey          = attribute.Key("db.mongodb.txn_number")
)

// Network transport values for the "network.transport" attribute.
const (
	TransportTCP  = "tcp"
	TransportUnix = "unix"
)

// noopTracer is used in place of a nil Tracer so that call sites never have to
// branch on whether tracing is enabled. Spans it produces are discarded, and
// the context it returns is the context it was given.
var noopTracer = noop.NewTracerProvider().Tracer("")

// Observer dispatches lifecycle moments to the observability sinks configured
// on a Client. A zero Observer is valid and discards everything.
//
// Observer is copied by value throughout the driver, so it must stay small and
// its fields must be safe for concurrent use.
type Observer struct {
	// CommandMonitor receives command monitoring events. If nil, or if the
	// relevant callback is nil, no events are published.
	CommandMonitor *event.CommandMonitor

	// Logger receives structured log messages. If nil, or if the relevant
	// component and level are not enabled, no messages are logged.
	Logger *logger.Logger

	// Tracer creates OpenTelemetry spans. If nil, no spans are recorded.
	Tracer trace.Tracer
}

// tracer returns a Tracer that is always safe to call.
func (o Observer) tracer() trace.Tracer {
	if o.Tracer == nil {
		return noopTracer
	}

	return o.Tracer
}

// commandLogEnabled reports whether command messages are being logged at debug
// level. Callers use this to avoid assembling log payloads that would be
// discarded.
func (o Observer) commandLogEnabled() bool {
	return o.Logger != nil && o.Logger.LevelComponentEnabled(logger.LevelDebug, logger.ComponentCommand)
}

// maxDocumentLength returns the configured command truncation width, or 0 if
// there is no logger.
func (o Observer) maxDocumentLength() uint {
	if o.Logger == nil {
		return 0
	}

	return o.Logger.MaxDocumentLength
}

// RecordError records err as an exception on span and marks the span as failed.
// The OpenTelemetry specification requires "exception.message" and
// "exception.type", which span.RecordError supplies. statusCode, when non-empty,
// is recorded as the MongoDB error code in "db.response.status_code".
func RecordError(span trace.Span, err error, statusCode string) {
	if err == nil || !span.IsRecording() {
		return
	}

	if statusCode != "" {
		span.SetAttributes(semconv.DBResponseStatusCode(statusCode))
	}

	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// OperationInfo describes a driver operation for the purpose of creating its
// operation span.
type OperationInfo struct {
	// Name is the driver operation name, which is the name of the command the
	// operation is implemented with (e.g. "findAndModify" for FindOneAndDelete).
	Name string

	// DatabaseName is the database the operation runs against.
	DatabaseName string

	// CollectionName is the collection the operation targets. It is empty for
	// operations that do not target a specific collection, in which case the
	// "db.collection.name" attribute is omitted.
	CollectionName string
}

// summary renders the "db.operation.summary" attribute and the span name:
// "<operation> <db>.<collection>", or "<operation> <db>" when there is no
// collection.
func (info OperationInfo) summary() string {
	if info.CollectionName == "" {
		return info.Name + " " + info.DatabaseName
	}

	return info.Name + " " + info.DatabaseName + "." + info.CollectionName
}

// OperationStarted starts the span for a driver operation. The returned context
// carries the span, so spans created for the commands the operation issues nest
// underneath it automatically. The caller is responsible for ending the span.
func (o Observer) OperationStarted(
	ctx context.Context,
	info OperationInfo,
) (context.Context, trace.Span) {
	summary := info.summary()

	attrs := make([]attribute.KeyValue, 0, 5)
	attrs = append(attrs,
		semconv.DBSystemNameMongoDB,
		semconv.DBNamespace(info.DatabaseName),
		semconv.DBOperationName(info.Name),
		dbOperationSummaryKey.String(summary),
	)
	if info.CollectionName != "" {
		attrs = append(attrs, semconv.DBCollectionName(info.CollectionName))
	}

	return o.tracer().Start(ctx, summary,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...))
}

// CommandStartedInfo describes a command about to be sent to the server.
//
// Command and the redaction decision recorded in Sensitive are made by the
// caller, because redaction depends on operation and session state that is not
// available here. Assembling them once and passing them in also avoids the
// duplicated redaction work the previous per-mechanism call sites performed.
type CommandStartedInfo struct {
	// Command is the command document, already redacted. It is nil for
	// sensitive commands.
	Command bson.Raw

	CommandName    string
	DatabaseName   string
	CollectionName string

	RequestID          int64
	ConnectionID       string
	DriverConnectionID int64
	ServerConnectionID *int64
	ServiceID          *bson.ObjectID

	// ServerAddress is the address of the server the command is sent to.
	ServerAddress string

	// NetworkTransport is TransportTCP or TransportUnix.
	NetworkTransport string

	// LSID is the hex-encoded logical session ID, empty if there is no session.
	LSID string

	// TxnNumber is the transaction number, nil outside of a transaction.
	TxnNumber *int64

	// Sensitive reports whether the command is security sensitive. Sensitive
	// commands get no span, as required by the OpenTelemetry specification.
	Sensitive bool
}

// querySummary renders the "db.query.summary" attribute:
// "<command> <db>.<collection>", or "<command> <db>" when the command does not
// target a collection.
func (info CommandStartedInfo) querySummary() string {
	if info.CollectionName == "" {
		return info.CommandName + " " + info.DatabaseName
	}

	return info.CommandName + " " + info.DatabaseName + "." + info.CollectionName
}

// loggerCommand builds the log payload shared by the started, succeeded, and
// failed command messages. host and port come from splitting ServerAddress.
func (info CommandStartedInfo) loggerCommand(message, host, port string) logger.Command {
	return logger.Command{
		DriverConnectionID: info.DriverConnectionID,
		Message:            message,
		Name:               info.CommandName,
		DatabaseName:       info.DatabaseName,
		RequestID:          info.RequestID,
		ServerConnectionID: info.ServerConnectionID,
		ServerHost:         host,
		ServerPort:         port,
		ServiceID:          info.ServiceID,
	}
}

// CommandFinishedInfo describes the outcome of a command.
type CommandFinishedInfo struct {
	CommandStartedInfo

	// Duration is how long the command took.
	Duration time.Duration

	// Reply is the server's reply, already redacted.
	Reply bson.Raw

	// Err is the command error, nil on success.
	Err error

	// StatusCode is the MongoDB error code as a string, empty if there is none.
	StatusCode string

	// Success reports whether the command executed on the server. A command
	// that returned write errors is a success: the command itself ran, only the
	// writes failed.
	Success bool
}

// CommandStarted starts the command span, publishes a CommandStartedEvent, and
// writes the "command started" log message, for whichever of those sinks is
// configured.
//
// The returned span must be passed to CommandFinished. The returned context
// carries the span, and is the caller's context unchanged if no span was
// created.
func (o Observer) CommandStarted(
	ctx context.Context,
	info CommandStartedInfo,
) (context.Context, trace.Span) {
	// Split the address once and share it between the log message and the span,
	// rather than once per mechanism.
	var host, port string
	if o.commandLogEnabled() || o.Tracer != nil {
		host, port, _ = net.SplitHostPort(info.ServerAddress)
	}

	if o.commandLogEnabled() {
		formattedCmd := logger.FormatDocument(info.Command, o.maxDocumentLength())

		o.Logger.Print(logger.LevelDebug,
			logger.ComponentCommand,
			logger.CommandStarted,
			logger.SerializeCommand(
				info.loggerCommand(logger.CommandStarted, host, port),
				logger.KeyCommand, formattedCmd)...)
	}

	if o.CommandMonitor != nil && o.CommandMonitor.Started != nil {
		o.CommandMonitor.Started(ctx, &event.CommandStartedEvent{
			Command:            info.Command,
			DatabaseName:       info.DatabaseName,
			CommandName:        info.CommandName,
			RequestID:          info.RequestID,
			ConnectionID:       info.ConnectionID,
			ServerConnectionID: info.ServerConnectionID,
			ServiceID:          info.ServiceID,
		})
	}

	// Sensitive commands must not be traced. Return a discarded span rather
	// than the parent span, so that the caller's End cannot end the operation
	// span, and return the caller's context so nesting is unaffected.
	if info.Sensitive {
		_, span := noopTracer.Start(ctx, info.CommandName)

		return ctx, span
	}

	return o.tracer().Start(ctx, info.CommandName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(info.spanAttributes(host, port)...))
}

// spanAttributes builds the command span's attributes.
func (info CommandStartedInfo) spanAttributes(host, port string) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 12)
	attrs = append(attrs,
		semconv.DBSystemNameMongoDB,
		semconv.DBNamespace(info.DatabaseName),
		dbCommandNameKey.String(info.CommandName),
		semconv.DBQuerySummary(info.querySummary()),
		semconv.ServerAddress(host),
		driverConnectionIDKey.Int64(info.DriverConnectionID),
	)

	if info.CollectionName != "" {
		attrs = append(attrs, semconv.DBCollectionName(info.CollectionName))
	}
	if p, err := strconv.Atoi(port); err == nil {
		attrs = append(attrs, semconv.ServerPort(p))
	}
	switch info.NetworkTransport {
	case TransportUnix:
		attrs = append(attrs, semconv.NetworkTransportUnix)
	default:
		attrs = append(attrs, semconv.NetworkTransportTCP)
	}
	if info.ServerConnectionID != nil {
		attrs = append(attrs, serverConnectionIDKey.Int64(*info.ServerConnectionID))
	}
	if info.LSID != "" {
		attrs = append(attrs, lsidKey.String(info.LSID))
	}
	if info.TxnNumber != nil {
		attrs = append(attrs, txnNumberKey.Int64(*info.TxnNumber))
	}

	return attrs
}

// CommandFinished ends the command span and publishes the succeeded or failed
// event and log message, for whichever of those sinks is configured. span must
// be the span returned by the corresponding CommandStarted call.
func (o Observer) CommandFinished(
	ctx context.Context,
	span trace.Span,
	info CommandFinishedInfo,
) {
	// Ending the span is unconditional so that no control flow in the caller
	// can leak it.
	defer span.End()

	if !info.Success {
		RecordError(span, info.Err, info.StatusCode)
	}

	if o.commandLogEnabled() {
		host, port, _ := net.SplitHostPort(info.ServerAddress)

		message := logger.CommandSucceeded
		key := logger.KeyReply
		formatted := logger.FormatDocument(info.Reply, o.maxDocumentLength())
		if !info.Success {
			message = logger.CommandFailed
			key = logger.KeyFailure
			formatted = logger.FormatString(info.Err.Error(), o.maxDocumentLength())
		}

		o.Logger.Print(logger.LevelDebug,
			logger.ComponentCommand,
			message,
			logger.SerializeCommand(
				info.loggerCommand(message, host, port),
				logger.KeyDurationMS, info.Duration.Milliseconds(),
				key, formatted)...)
	}

	if o.CommandMonitor == nil {
		return
	}
	if info.Success && o.CommandMonitor.Succeeded == nil {
		return
	}
	if !info.Success && o.CommandMonitor.Failed == nil {
		return
	}

	finished := event.CommandFinishedEvent{
		CommandName:        info.CommandName,
		DatabaseName:       info.DatabaseName,
		RequestID:          info.RequestID,
		ConnectionID:       info.ConnectionID,
		Duration:           info.Duration,
		ServerConnectionID: info.ServerConnectionID,
		ServiceID:          info.ServiceID,
	}

	if info.Success {
		o.CommandMonitor.Succeeded(ctx, &event.CommandSucceededEvent{
			Reply:                info.Reply,
			CommandFinishedEvent: finished,
		})

		return
	}

	o.CommandMonitor.Failed(ctx, &event.CommandFailedEvent{
		Failure:              info.Err,
		CommandFinishedEvent: finished,
	})
}
