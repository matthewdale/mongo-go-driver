// Copyright (C) MongoDB, Inc. 2017-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package bsonrw

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

type jsonTokenType byte

const (
	jttBeginObject jsonTokenType = iota
	jttEndObject
	jttBeginArray
	jttEndArray
	jttColon
	jttComma
	jttInt32
	jttInt64
	jttDouble
	jttString
	jttBool
	jttNull
	jttEOF
)

type jsonToken struct {
	t jsonTokenType
	v interface{}
	p int
}

type jsonScanner struct {
	dec     *json.Decoder
	delims  []json.Delim
	isKey   bool
	isColon bool
	isComma bool
}

func push(stack []json.Delim, val json.Delim) []json.Delim {
	return append(stack, val)
}

func pop(stack []json.Delim) ([]json.Delim, json.Delim) {
	val := stack[len(stack)-1]
	return stack[:len(stack)-1], val
}

func peek(stack []json.Delim) json.Delim {
	return stack[len(stack)-1]
}

// nextToken returns the next JSON token if one exists. A token is a character
// of the JSON grammar, a number, a string, or a literal.
func (js *jsonScanner) nextToken() (*jsonToken, error) {
	if js.delims == nil {
		js.delims = make([]json.Delim, 0)
	}

	if js.isColon {
		// fmt.Println("returning colon")
		js.isColon = false
		return &jsonToken{t: jttColon, v: byte(':')}, nil
	}
	if js.isComma {
		// fmt.Println("returning comma")
		js.isComma = false
		return &jsonToken{t: jttComma, v: byte(',')}, nil
	}

	js.dec.UseNumber()
	token, err := js.dec.Token()
	if err == io.EOF {
		return &jsonToken{t: jttEOF}, nil
	}
	if err != nil {
		return nil, err
	}

	// fmt.Printf("token: %v", token)
	// defer func() {
	// 	fmt.Printf(
	// 		"; state = delims: %v, isKey: %t, isColon: %t, isComma: %t\n",
	// 		js.delims,
	// 		js.isKey,
	// 		js.isColon,
	// 		js.isComma)
	// }()

	// If we're in a JSON object, flip-flop between key and value.
	if len(js.delims) > 0 && peek(js.delims) == '{' {
		js.isKey = !js.isKey
	}

	if js.isKey {
		switch token.(type) {
		case string:
			js.isColon = true
		case json.Delim:
			js.isKey = false
		default:
			return nil, fmt.Errorf("object keys must be strings, got %T (%q)", token, token)
		}
	}

	more := js.dec.More()
	js.isComma = more && len(js.delims) > 0 &&
		((peek(js.delims) == '{' && !js.isKey) ||
			(peek(js.delims) == '['))

	if token == nil {
		return &jsonToken{t: jttNull}, nil
	}

	// TODO: How do we set "p" position? Maybe just say "after last token %s"? Seems to only be used for errors.
	switch val := token.(type) {
	case json.Delim:
		var t jsonTokenType
		switch val {
		case '{':
			js.isKey = false
			js.isComma = false
			js.delims = push(js.delims, val)
			t = jttBeginObject
		case '}':
			js.delims, _ = pop(js.delims)
			t = jttEndObject
		case '[':
			js.isKey = false
			js.isComma = false
			js.delims = push(js.delims, val)
			t = jttBeginArray
		case ']':
			js.delims, _ = pop(js.delims)
			t = jttEndArray
		}

		return &jsonToken{t: t, v: byte(val)}, nil
	case bool:
		return &jsonToken{t: jttBool, v: val}, nil
	case float64:
		return nil, fmt.Errorf("unreachable state float64, expected json.Number for value %f", val)
	case json.Number:
		if int64Val, err := strconv.ParseInt(string(val), 10, 64); err == nil {
			if int64Val < math.MinInt32 || int64Val > math.MaxInt32 {
				return &jsonToken{t: jttInt64, v: int64Val}, nil
			}

			int32Val := int32(int64Val)
			return &jsonToken{t: jttInt32, v: int32Val}, nil
		}

		if floatVal, err := strconv.ParseFloat(string(val), 64); err == nil {
			return &jsonToken{t: jttDouble, v: floatVal}, nil
		}

		return nil, fmt.Errorf("error parsing json.Number %q", val)
	case string:
		return &jsonToken{t: jttString, v: val}, nil
	}

	return nil, errors.New("invalid JSON input")
}
