package bson_test

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Motivation:
// Currently, using the "go.mongodb.org/mongo-driver/bson" package to declare BSON document literals
// in the documented way
//
//   bson.D{{"foo", "bar"}}
//
// causes the standard Go "vet" tool to print the message:
//
//   go.mongodb.org/mongo-driver/bson/primitive.E composite literal uses unkeyed fields
//
// because the bson.E type contains fields "Key" and "Value" that are unkeyed in the BSON document
// literal example.
//
// Find a way to define BSON document literals that doesn't cause the "unkeyed fields" vet warning.

// See related Stack Overflow post:
// https://stackoverflow.com/questions/54548441/composite-literal-uses-unkeyed-fields/66172486

func TestComplexDocument(t *testing.T) {
	// Existing standard way to define BSON document literals.
	_ = bson.D{
		{"foo", "bar"},
		{"baz", int64(-27)},
		{"bing", bson.A{nil, primitive.Regex{Pattern: "word", Options: "i"}}},
		// {time.Now(), int64(-27)}, // This should cause a compile error and does.
	}

	// Existing standard way to define BSON map literals.
	_ = bson.M{
		"foo":  "bar",
		"baz":  int64(-27),
		"bing": bson.A{nil, primitive.Regex{Pattern: "word", Options: "i"}},
	}

	// Existing standard way to define BSON array literals.
	_ = bson.A{
		"foo", "bar", "baz", "bing",
	}

	// Experimental way to define BSON document literals using an element helper function with
	// signature:
	//
	//   func(key string, value interface{}) bson.E
	//
	// Pros:
	//   - Compile-time key type checking.
	// Cons:
	_ = bson.D{
		bson.E2("foo", "bar"),
		bson.E2("baz", int64(-27)),
		bson.E2("bing", bson.A{nil, primitive.Regex{Pattern: "word", Options: "i"}}),
		// bson.E2(time.Now(), int64(-27)), // This should cause a compile error and does.
	}

	// Experimental way to define BSON document literals using a type
	//
	//   type D2 [][2]interface{}
	//
	// Pros:
	//   - BSON document literal syntax is almost exactly the same as existing.
	// Cons:
	//   - Only string keys are invalid, but the type [2]interface{} can compile with any type key.
	_ = bson.D2{
		{"foo", "bar"},
		{"baz", int64(-27)},
		{"bing", bson.A{nil, primitive.Regex{Pattern: "word", Options: "i"}}},
		{time.Now(), int64(-27)}, // This should cause a compile error but doesn't.
	}.ToD()

	// Experimental way to define BSON document literals using a builder.
	//
	// Pros:
	//   - Compile-time key type checking.
	// Cons:
	//   - This syntax causes some editors to erroneously continue indenting the next line until
	//     gofmt fixes it, which is annoying!
	//   - Lines can't be added or removed without adjusting periods because "trailing periods"
	//     aren't valid like "trailing commas" are.
	_ = bson.D3().
		E("foo", "bar").
		E("baz", int64(-27)).
		E("bing", bson.A{nil, primitive.Regex{Pattern: "word", Options: "i"}})
	// E(time.Now(), int64(-27)) // This should cause a compile error and does.

	// Experimental way to define BSON document literals using a document helper function with
	// signature:
	//
	//   func(elements ...bson.E) bson.D
	//
	// and an element helper function with signature:
	//
	//   func(key string, value interface{}) bson.E
	//
	// Pros:
	// Cons:
	_ = bson.D4(
		bson.E2("foo", "bar"),
		bson.E2("baz", int64(-27)),
		bson.E2("bing", bson.A{nil, primitive.Regex{Pattern: "word", Options: "i"}}),
		// bson.E2(time.Now(), int64(-27)), // This should cause a compile error and does.
	)
}

func TestSimpleDocument(t *testing.T) {
	_ = bson.D{{"foo", "bar"}}

	_ = bson.M{"foo": "bar"}

	_ = bson.A{"foo"}

	_ = bson.D{bson.E2("foo", "bar")}

	_ = bson.D2{{"foo", "bar"}}

	_ = bson.D3().E("foo", "bar")

	_ = bson.D4(bson.E2("foo", "bar"))
}

func TestPipeline(t *testing.T) {
	_ = mongo.Pipeline{
		{
			{"$match", bson.D{
				{"items.fruit", "banana"},
			}},
		},
		{
			{"$sort", bson.D{
				{"date", 1},
			}},
		},
	}

	_ = mongo.Pipeline{
		{
			bson.E2("$match", bson.D{
				bson.E2("$items.fruit", "banana"),
			}),
		},
		{
			bson.E2("$sort", bson.D{
				bson.E2("date", 1),
			}),
		},
	}

	_ = mongo.Pipeline{
		bson.D2{
			{"$match", bson.D2{
				{"$item.fruit", "banana"},
			}},
		}.ToD(),
		bson.D2{
			{"$sort", bson.D2{
				{"date", 1},
			}},
		}.ToD(),
	}

	_ = mongo.Pipeline{
		bson.D3().
			E("$match", bson.D3().
				E("$item.fruit", "banana")).ToD(),
		bson.D3().E("$sort", bson.D3().
			E("date", 1)).ToD(),
	}

	_ = mongo.Pipeline{
		bson.D4(
			bson.E2("$match", bson.D4(
				bson.E2("$items.fruit", "banana"),
			)),
		),
		bson.D4(
			bson.E2("$sort", bson.D4(
				bson.E2("date", 1),
			)),
		),
	}
}
