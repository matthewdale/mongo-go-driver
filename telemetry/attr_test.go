// Copyright (C) MongoDB, Inc. 2026-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package telemetry

import (
	"math"
	"testing"

	"go.mongodb.org/mongo-driver/v2/internal/assert"
)

func TestAttrRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("string", func(t *testing.T) {
		t.Parallel()

		a := String("key", "value")
		assert.Equal(t, "key", a.Key())
		assert.Equal(t, KindString, a.Kind())
		assert.Equal(t, "value", a.AsString())
	})
	t.Run("empty string is still KindString", func(t *testing.T) {
		t.Parallel()

		a := String("key", "")
		assert.Equal(t, KindString, a.Kind())
		assert.Equal(t, "", a.AsString())
	})
	t.Run("int64", func(t *testing.T) {
		t.Parallel()

		for _, v := range []int64{0, 1, -1, math.MaxInt64, math.MinInt64} {
			a := Int64("key", v)
			assert.Equal(t, KindInt64, a.Kind())
			assert.Equal(t, v, a.AsInt64())
		}
	})
	t.Run("int widens to int64", func(t *testing.T) {
		t.Parallel()

		a := Int("key", -42)
		assert.Equal(t, KindInt64, a.Kind())
		assert.Equal(t, int64(-42), a.AsInt64())
	})
	t.Run("float64", func(t *testing.T) {
		t.Parallel()

		for _, v := range []float64{0, 1.5, -1.5, math.MaxFloat64, math.SmallestNonzeroFloat64} {
			a := Float64("key", v)
			assert.Equal(t, KindFloat64, a.Kind())
			assert.Equal(t, v, a.AsFloat64())
		}
	})
	t.Run("float64 NaN", func(t *testing.T) {
		t.Parallel()

		assert.True(t, math.IsNaN(Float64("key", math.NaN()).AsFloat64()),
			"expected NaN to survive the round trip")
	})
	t.Run("bool", func(t *testing.T) {
		t.Parallel()

		assert.True(t, Bool("key", true).AsBool(), "expected true")
		assert.False(t, Bool("key", false).AsBool(), "expected false")
		assert.Equal(t, KindBool, Bool("key", false).Kind())
	})
	t.Run("string slice", func(t *testing.T) {
		t.Parallel()

		v := []string{"a", "b"}
		a := StringSlice("key", v)
		assert.Equal(t, KindStringSlice, a.Kind())
		assert.Equal(t, v, a.AsStringSlice())
	})
	t.Run("int64 slice", func(t *testing.T) {
		t.Parallel()

		v := []int64{1, 2}
		a := Int64Slice("key", v)
		assert.Equal(t, KindInt64Slice, a.Kind())
		assert.Equal(t, v, a.AsInt64Slice())
	})
	t.Run("float64 slice", func(t *testing.T) {
		t.Parallel()

		v := []float64{1.5, 2.5}
		a := Float64Slice("key", v)
		assert.Equal(t, KindFloat64Slice, a.Kind())
		assert.Equal(t, v, a.AsFloat64Slice())
	})
	t.Run("bool slice", func(t *testing.T) {
		t.Parallel()

		v := []bool{true, false}
		a := BoolSlice("key", v)
		assert.Equal(t, KindBoolSlice, a.Kind())
		assert.Equal(t, v, a.AsBoolSlice())
	})
}

func TestAttrZeroValue(t *testing.T) {
	t.Parallel()

	var a Attr

	assert.Equal(t, KindInvalid, a.Kind())
	assert.Equal(t, "", a.Key())
	assert.Equal(t, "", a.AsString())
	assert.Equal(t, int64(0), a.AsInt64())
	assert.Nil(t, a.AsStringSlice(), "expected nil string slice")
}

// TestAttrMismatchedAccessor asserts that reading an Attr with the wrong
// accessor returns a zero value rather than panicking or returning garbage from
// the shared "num" field. Tracer implementations switch on Kind, but a buggy one
// must not be able to crash the driver.
func TestAttrMismatchedAccessor(t *testing.T) {
	t.Parallel()

	// Int64 and Float64 share the num field, so this is the pair most likely to
	// leak a nonsense value if the Kind guard is dropped.
	f := Float64("key", 1.5)
	assert.Equal(t, int64(0), f.AsInt64())

	i := Int64("key", 42)
	assert.Equal(t, float64(0), i.AsFloat64())

	assert.Equal(t, "", i.AsString())
	assert.False(t, i.AsBool(), "expected false")
	assert.Nil(t, i.AsInt64Slice(), "expected nil slice")

	// The slice accessors share the "slice" field, so a mismatched read must be
	// guarded by Kind rather than by the type assertion alone.
	ss := StringSlice("key", []string{"a"})
	assert.Nil(t, ss.AsInt64Slice(), "expected nil slice")
}

// TestAttrScalarConstructorsDoNotAllocate is the assertion the Enabled() gate
// design rests on: building attributes for a span must not allocate, so the
// only cost of tracing on the hot path is the slice holding them.
//
// This test cannot call t.Parallel: testing.AllocsPerRun panics if it runs
// concurrently with another test.
func TestAttrScalarConstructorsDoNotAllocate(t *testing.T) {
	tests := []struct {
		name string
		fn   func()
	}{
		{"String", func() { _ = String("key", "value") }},
		{"Int64", func() { _ = Int64("key", 42) }},
		{"Int", func() { _ = Int("key", 42) }},
		{"Float64", func() { _ = Float64("key", 1.5) }},
		{"Bool", func() { _ = Bool("key", true) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := testing.AllocsPerRun(100, test.fn)
			assert.Equal(t, float64(0), got,
				"expected %s to allocate 0 times, got %v", test.name, got)
		})
	}
}

func TestKindString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "Invalid", KindInvalid.String())
	assert.Equal(t, "String", KindString.String())
	assert.Equal(t, "BoolSlice", KindBoolSlice.String())
	assert.Equal(t, "Kind(99)", Kind(99).String())
}
