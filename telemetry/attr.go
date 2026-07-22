// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package telemetry

import (
	"math"
	"strconv"
)

// Kind describes the type of the value held by an [Attr].
//
// New Kind values may be added in any release. A [Tracer] implementation must
// skip an Attr whose Kind it does not recognize rather than treating it as an
// error.
type Kind int

// The set of value types an [Attr] can hold.
const (
	KindInvalid Kind = iota
	KindString
	KindInt64
	KindFloat64
	KindBool
	KindStringSlice
	KindInt64Slice
	KindFloat64Slice
	KindBoolSlice
)

// String returns the name of the Kind.
func (k Kind) String() string {
	switch k {
	case KindInvalid:
		return "Invalid"
	case KindString:
		return "String"
	case KindInt64:
		return "Int64"
	case KindFloat64:
		return "Float64"
	case KindBool:
		return "Bool"
	case KindStringSlice:
		return "StringSlice"
	case KindInt64Slice:
		return "Int64Slice"
	case KindFloat64Slice:
		return "Float64Slice"
	case KindBoolSlice:
		return "BoolSlice"
	}

	return "Kind(" + strconv.Itoa(int(k)) + ")"
}

// Attr is a key/value pair attached to a [Span].
//
// Construct an Attr with [String], [Int], [Int64], [Float64], [Bool], or one of
// the slice constructors. The zero Attr has Kind [KindInvalid] and must be
// ignored by [Tracer] implementations.
//
// Read an Attr's value with the accessor matching its Kind. An accessor that
// does not match the Attr's Kind returns the zero value for its type rather
// than panicking.
// Attr is deliberately larger than it strictly needs to be: string values get
// a dedicated field rather than being boxed into the "slice" any, because
// storing a string in an interface forces a heap allocation and strings are by
// far the most common attribute type on the driver's hot path.
type Attr struct {
	key   string
	str   string // KindString only
	num   uint64 // int64, float64 bits, or bool as 0 or 1
	slice any    // slice payloads only; nil for scalar kinds
	kind  Kind
}

// Key returns the attribute's key.
func (a Attr) Key() string { return a.key }

// Kind returns the type of the attribute's value.
func (a Attr) Kind() Kind { return a.kind }

// AsString returns the attribute's value as a string. It returns "" if the
// attribute's Kind is not [KindString].
func (a Attr) AsString() string {
	if a.kind != KindString {
		return ""
	}

	return a.str
}

// AsInt64 returns the attribute's value as an int64. It returns 0 if the
// attribute's Kind is not [KindInt64].
func (a Attr) AsInt64() int64 {
	if a.kind != KindInt64 {
		return 0
	}

	return int64(a.num)
}

// AsFloat64 returns the attribute's value as a float64. It returns 0 if the
// attribute's Kind is not [KindFloat64].
func (a Attr) AsFloat64() float64 {
	if a.kind != KindFloat64 {
		return 0
	}

	return math.Float64frombits(a.num)
}

// AsBool returns the attribute's value as a bool. It returns false if the
// attribute's Kind is not [KindBool].
func (a Attr) AsBool() bool {
	if a.kind != KindBool {
		return false
	}

	return a.num != 0
}

// AsStringSlice returns the attribute's value as a []string. It returns nil if
// the attribute's Kind is not [KindStringSlice].
//
// The returned slice is not a copy. A [Tracer] implementation must not modify
// it.
func (a Attr) AsStringSlice() []string {
	if a.kind != KindStringSlice {
		return nil
	}

	s, _ := a.slice.([]string)

	return s
}

// AsInt64Slice returns the attribute's value as an []int64. It returns nil if
// the attribute's Kind is not [KindInt64Slice].
//
// The returned slice is not a copy. A [Tracer] implementation must not modify
// it.
func (a Attr) AsInt64Slice() []int64 {
	if a.kind != KindInt64Slice {
		return nil
	}

	s, _ := a.slice.([]int64)

	return s
}

// AsFloat64Slice returns the attribute's value as a []float64. It returns nil
// if the attribute's Kind is not [KindFloat64Slice].
//
// The returned slice is not a copy. A [Tracer] implementation must not modify
// it.
func (a Attr) AsFloat64Slice() []float64 {
	if a.kind != KindFloat64Slice {
		return nil
	}

	s, _ := a.slice.([]float64)

	return s
}

// AsBoolSlice returns the attribute's value as a []bool. It returns nil if the
// attribute's Kind is not [KindBoolSlice].
//
// The returned slice is not a copy. A [Tracer] implementation must not modify
// it.
func (a Attr) AsBoolSlice() []bool {
	if a.kind != KindBoolSlice {
		return nil
	}

	s, _ := a.slice.([]bool)

	return s
}

// String returns an Attr holding a string value.
func String(key, value string) Attr {
	return Attr{key: key, kind: KindString, str: value}
}

// Int64 returns an Attr holding an int64 value.
func Int64(key string, value int64) Attr {
	return Attr{key: key, kind: KindInt64, num: uint64(value)}
}

// Int returns an Attr holding an int value, widened to an int64.
func Int(key string, value int) Attr {
	return Int64(key, int64(value))
}

// Float64 returns an Attr holding a float64 value.
func Float64(key string, value float64) Attr {
	return Attr{key: key, kind: KindFloat64, num: math.Float64bits(value)}
}

// Bool returns an Attr holding a bool value.
func Bool(key string, value bool) Attr {
	var num uint64
	if value {
		num = 1
	}

	return Attr{key: key, kind: KindBool, num: num}
}

// StringSlice returns an Attr holding a []string value. The slice is not
// copied and must not be modified after the Attr is created.
func StringSlice(key string, value []string) Attr {
	return Attr{key: key, kind: KindStringSlice, slice: value}
}

// Int64Slice returns an Attr holding an []int64 value. The slice is not copied
// and must not be modified after the Attr is created.
func Int64Slice(key string, value []int64) Attr {
	return Attr{key: key, kind: KindInt64Slice, slice: value}
}

// Float64Slice returns an Attr holding a []float64 value. The slice is not
// copied and must not be modified after the Attr is created.
func Float64Slice(key string, value []float64) Attr {
	return Attr{key: key, kind: KindFloat64Slice, slice: value}
}

// BoolSlice returns an Attr holding a []bool value. The slice is not copied and
// must not be modified after the Attr is created.
func BoolSlice(key string, value []bool) Attr {
	return Attr{key: key, kind: KindBoolSlice, slice: value}
}
