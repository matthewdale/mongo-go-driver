// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package telemetryutil holds the span names and attribute keys the driver
// emits, along with helpers for building attributes from driver types.
//
// These values are internal so that they can be changed without a public API
// change while the telemetry API is experimental. They are, however, observable
// by users through the spans the driver produces, so treat a change to one as a
// user-visible change.
package telemetryutil

import (
	"net"
	"strconv"

	"go.mongodb.org/mongo-driver/v2/mongo/address"
	"go.mongodb.org/mongo-driver/v2/telemetry"
)

// Span names.
//
// Names of spans that wrap a specific command are the command name itself, for
// example "insert", and so are not listed here.
const (
	SpanServerSelection    = "server selection"
	SpanConnectionCheckout = "connection checkout"
)

// Attribute keys taken from the OpenTelemetry semantic conventions for database
// clients. The driver uses the conventional keys so that plugins do not have to
// remap them, but does not import OpenTelemetry to produce them.
const (
	AttrDBSystemName     = "db.system.name"
	AttrDBNamespace      = "db.namespace"
	AttrDBCollectionName = "db.collection.name"
	AttrDBOperationName  = "db.operation.name"
	AttrServerAddress    = "server.address"
	AttrServerPort       = "server.port"
	AttrErrorType        = "error.type"
)

// Attribute keys specific to this driver, for which no semantic convention
// exists. The "db.mongodb." prefix marks them as ours.
const (
	AttrRetryAttempt       = "db.mongodb.retry_attempt"
	AttrPinnedConnection   = "db.mongodb.pinned"
	AttrServerConnectionID = "db.mongodb.server_connection_id"
	AttrDeprioritizedCount = "db.mongodb.deprioritized_count"
)

// DBSystemName is the value of the AttrDBSystemName attribute for every span
// the driver produces.
var DBSystemName = telemetry.String(AttrDBSystemName, "mongodb")

// ServerAddress converts a server address into server.address and server.port
// attributes, appending them to dst.
//
// A Unix domain socket has no port, so only server.address is appended for one.
// If the address cannot be split, it is reported whole as server.address rather
// than being dropped, on the grounds that a slightly wrong address is more
// useful in a trace than no address.
func ServerAddress(dst []telemetry.Attr, addr address.Address) []telemetry.Attr {
	s := addr.String()
	if s == "" {
		return dst
	}

	if addr.Network() == "unix" {
		return append(dst, telemetry.String(AttrServerAddress, s))
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return append(dst, telemetry.String(AttrServerAddress, s))
	}

	dst = append(dst, telemetry.String(AttrServerAddress, host))

	// A non-numeric port is not something the driver can produce, but reporting
	// no port is better than reporting a wrong one.
	if p, err := strconv.Atoi(port); err == nil {
		dst = append(dst, telemetry.Int(AttrServerPort, p))
	}

	return dst
}
