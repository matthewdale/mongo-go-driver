// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// Package telemetry defines a platform-agnostic API for tracing the work the
// MongoDB Go Driver performs on behalf of an operation.
//
// The driver does not depend on any tracing platform. Instead it defines the
// [Tracer] and [Span] interfaces here, and support for a specific platform is
// provided by a separate module that adapts that platform to these interfaces.
// OpenTelemetry support lives in the go.mongodb.org/mongo-driver/ext/otelplugin
// module.
//
// To enable tracing, pass an implementation to
// [go.mongodb.org/mongo-driver/v2/mongo/options.ClientOptions.SetTracer].
//
// # Experimental
//
// This package is experimental. Its API is unstable, is not covered by the
// MongoDB Go Driver's semantic-versioning guarantees, and may change in
// backward-incompatible ways or be removed entirely in any release, including a
// patch release. Pin an exact driver version and review the changelog before
// upgrading.
//
// This package is not the subject of a MongoDB driver specification. Span
// names, attribute keys, and the set of operations that produce spans are not
// guaranteed to match those of any other MongoDB driver, and may change between
// driver releases.
//
// # Stability policy for implementers
//
// [Tracer] and [Span] are plain interfaces, and methods may be added to either
// in any release. Adding a method breaks existing implementations at compile
// time; that is an accepted cost of keeping this experimental API small and
// idiomatic while it evolves. Implementers should expect to make small updates
// when upgrading the driver.
//
// Two rules keep implementations forward-compatible with data the driver adds
// without changing any signature:
//
//   - New [Kind] values may be added in any release. Skip an [Attr] whose Kind
//     you do not recognize rather than treating it as an error.
//   - New attribute keys and span names may be added in any release. Do not
//     assume the set is closed.
//
// # Attribute naming
//
// Where an OpenTelemetry semantic convention exists for a value, the driver
// uses that convention's key, for example db.namespace, db.operation.name, and
// server.address. Keys specific to this driver are prefixed with "db.mongodb.",
// for example db.mongodb.retry_attempt. The driver does not import
// OpenTelemetry to produce these keys; they are string literals.
package telemetry
