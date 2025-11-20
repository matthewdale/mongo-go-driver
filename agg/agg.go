package agg

import (
	"go.mongodb.org/mongo-driver/v2/bson"
)

type NumberTypes interface {
	~int8 | ~int16 | ~int32 | ~int64 | ~int |
		~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uint | ~uintptr |
		~float32 | ~float64
}

type Pipeline []Stage

func (p Pipeline) MarshalBSON() ([]byte, error) {
	stages := make([]bson.D, len(p))
	for i, stage := range p {
		stages[i] = bson.D(stage)
	}
	return bson.Marshal(bson.D{{Key: "pipeline", Value: stages}})
}

func (p Pipeline) String() string {
	ej, err := bson.MarshalExtJSONIndent(p, false, false, "", "  ")
	if err != nil {
		return "<error>"
	}
	return string(ej)
}

type Stage bson.D

type SortOrder any

var (
	SortAscending  SortOrder = 1
	SortDescending SortOrder = -1
	SortTextScore  SortOrder = bson.D{{Key: "$meta", Value: "textScore"}}
)

// func SortStage[T FieldSpec[SortOrder] | Expression](sort ...T) Stage {
// 	return Stage{{Key: "$sort", Value: sort}}
// }

// type GroupKey []FieldSpec[Expression]

// func GroupBy(fields ...FieldSpec[Expression]) GroupKey {
// 	gk := make(GroupKey, 0, len(fields))
// 	for _, f := range fields {
// 		gk = append(gk, FieldSpec[Expression]{
// 			name: f.name,
// 			expr: f.expr,
// 		})
// 	}
// 	return gk
// }

// func GroupStage[T GroupKey | Expression | ~string](_id T, field ...FieldSpec[Accumulator]) Stage {
// 	fields := make(bson.D, 0, len(field))
// 	fields = append(fields, bson.E{Key: "_id", Value: _id})
// 	for _, f := range field {
// 		fields = append(fields, bson.E{Key: f.name, Value: f.expr})
// 	}
// 	return Stage{{Key: "$group", Value: fields}}
// }

type FieldSpec[T any] struct {
	name string
	expr T
}

func Field(name string, expr Expression) FieldSpec[Expression] {
	return FieldSpec[Expression]{
		name: name,
		expr: expr,
	}
}

func AccField(name string, acc Accumulator) FieldSpec[Accumulator] {
	return FieldSpec[Accumulator]{
		name: name,
		expr: acc,
	}
}

// func SortBy(field string, order SortOrder) FieldSpec[SortOrder] {
// 	return FieldSpec[SortOrder]{
// 		name: field,
// 		expr: order,
// 	}
// }

type SortSpec struct {
	expr any
}

func SortBy(field string, order SortOrder) SortSpec {
	return SortSpec{
		expr: bson.D{{Key: field, Value: order}},
	}
}

func ExpressionSortSpec(expr Expression) SortSpec {
	return SortSpec{
		expr: expr,
	}
}

func SortStage(sort ...SortSpec) Stage {
	return Stage{{Key: "$sort", Value: sort}}
}

type groupKey []FieldSpec[Expression]

func (groupKey) Expression() {}

func GroupBy(fields ...FieldSpec[Expression]) Expression {
	gk := make(groupKey, 0, len(fields))
	for _, f := range fields {
		gk = append(gk, FieldSpec[Expression]{
			name: f.name,
			expr: f.expr,
		})
	}
	return gk
}

func GroupStage(_id Expression, field ...FieldSpec[Accumulator]) Stage {
	fields := make(bson.D, 0, len(field))
	fields = append(fields, bson.E{Key: "_id", Value: _id})
	for _, f := range field {
		fields = append(fields, bson.E{Key: f.name, Value: f.expr})
	}
	return Stage{{Key: "$group", Value: fields}}
}

func SetStage(expression ...FieldSpec[Expression]) Stage {
	doc := make(bson.D, 0, len(expression))
	for _, ne := range expression {
		doc = append(doc, bson.E{Key: ne.name, Value: ne.expr})
	}
	return Stage{{Key: "$set", Value: doc}}
}

func ProjectStage(specification ...FieldSpec[Expression]) Stage {
	doc := make(bson.D, 0, len(specification))
	for _, ne := range specification {
		doc = append(doc, bson.E{Key: ne.name, Value: ne.expr})
	}
	return Stage{{Key: "$project", Value: doc}}
}

func UnsetStage(fields ...string) Stage {
	return Stage{{Key: "$unset", Value: fields}}
}

func ReplaceWithStage(expression ResolvesToObject) Stage {
	return Stage{{Key: "$replaceWith", Value: expression}}
}

func MatchStage(query Expression) Stage {
	return Stage{{Key: "$match", Value: query}}
}

type Accumulator struct {
	doc bson.D
}

func (a Accumulator) MarshalBSON() ([]byte, error) {
	return bson.Marshal(a.doc)
}

func LastNAcc(input ResolvesToArray, n ResolvesToNumber) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$lastN", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "n", Value: n},
		}}},
	}
}

func AvgAcc(expr ResolvesToNumber) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$avg", Value: expr}},
	}
}

func SumAcc(expr ResolvesToNumber) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$sum", Value: expr}},
	}
}

func MinAcc(expr ResolvesToNumber) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$min", Value: expr}},
	}
}

func MaxAcc(expr ResolvesToNumber) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$max", Value: expr}},
	}
}

func PercentileAcc(input ResolvesToNumber, p ResolvesToArray) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$percentile", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "p", Value: p},
			// TODO: Currently the method must always be "approximate". Do we need an argument for that?
			{Key: "method", Value: "approximate"},
		}}},
	}
}

type Expression interface {
	Expression()
}

type ResolvesToNumber interface {
	Expression
	ResolvesToNumber()
}

type ResolvesToInt interface {
	Expression
	ResolvesToNumber
	ResolvesToInt()
}

type ResolvesToLong interface {
	Expression
	ResolvesToNumber
	ResolvesToLong()
}

type ResolvesToDouble interface {
	Expression
	ResolvesToNumber
	ResolvesToDouble()
}

type ResolvesToBool interface {
	Expression
	ResolvesToBool()
}

type ResolvesToArray interface {
	Expression
	ResolvesToArray()
}

type ResolvesToObject interface {
	Expression
	ResolvesToObject()
}

type ResolvesToAny interface {
	Expression
	resolvesToNumber
	ResolvesToInt
	ResolvesToLong
	ResolvesToDouble
	ResolvesToBool
	ResolvesToArray
	ResolvesToObject
}

type expression struct {
	expr any
}

func (expression) Expression() {}

func (e expression) MarshalBSONValue() (byte, []byte, error) {
	t, v, err := bson.MarshalValue(e.expr)
	return byte(t), v, err
}

func Expr(expr any) Expression {
	return expression{expr: expr}
}

type resolvesToNumber struct {
	expr any
}

func (resolvesToNumber) Expression()       {}
func (resolvesToNumber) ResolvesToNumber() {}

func (rtn resolvesToNumber) MarshalBSONValue() (byte, []byte, error) {
	t, v, err := bson.MarshalValue(rtn.expr)
	return byte(t), v, err
}

type resolvesToInt struct {
	expr any
}

func (resolvesToInt) Expression()       {}
func (resolvesToInt) ResolvesToNumber() {}
func (resolvesToInt) ResolvesToInt()    {}

func (rti resolvesToInt) MarshalBSONValue() (byte, []byte, error) {
	t, v, err := bson.MarshalValue(rti.expr)
	return byte(t), v, err
}

type resolvesToBool struct {
	expr any
}

func (resolvesToBool) Expression()     {}
func (resolvesToBool) ResolvesToBool() {}

func (rtb resolvesToBool) MarshalBSONValue() (byte, []byte, error) {
	t, v, err := bson.MarshalValue(rtb.expr)
	return byte(t), v, err
}

type resolvesToArray struct {
	expr any
}

func (resolvesToArray) Expression()      {}
func (resolvesToArray) ResolvesToArray() {}

func (rta resolvesToArray) MarshalBSONValue() (byte, []byte, error) {
	t, v, err := bson.MarshalValue(rta.expr)
	return byte(t), v, err
}

type resolvesToObject struct {
	expr any
}

func (resolvesToObject) Expression()       {}
func (resolvesToObject) ResolvesToObject() {}

func (rto resolvesToObject) MarshalBSONValue() (byte, []byte, error) {
	t, v, err := bson.MarshalValue(rto.expr)
	return byte(t), v, err
}

type resolvesToAny struct {
	expr any
}

func (resolvesToAny) Expression()
func (resolvesToAny) ResolvesToArray()
func (resolvesToAny) ResolvesToBool()
func (resolvesToAny) ResolvesToDouble()
func (resolvesToAny) ResolvesToInt()
func (resolvesToAny) ResolvesToLong()
func (resolvesToAny) ResolvesToNumber()
func (resolvesToAny) ResolvesToObject()

func (rto resolvesToAny) MarshalBSONValue() (byte, []byte, error) {
	t, v, err := bson.MarshalValue(rto.expr)
	return byte(t), v, err
}

func NumberField(name string) ResolvesToNumber {
	return resolvesToNumber{expr: name}
}

func ObjectField(name string) ResolvesToObject {
	return resolvesToObject{expr: name}
}

func ArrayField(name string) ResolvesToArray {
	return resolvesToArray{expr: name}
}

func Number[T NumberTypes](value T) ResolvesToNumber {
	return resolvesToNumber{expr: value}
}

func Array[T any](values []T) resolvesToArray {
	return resolvesToArray{expr: values}
}

func RootObject() ResolvesToObject {
	return resolvesToObject{
		expr: "$$ROOT",
	}
}

func Abs(expr ResolvesToNumber) ResolvesToNumber {
	return resolvesToNumber{expr: expr}
}

type bitOr struct {
	expr any
}

func (bitOr) Expression()       {}
func (bitOr) ResolvesToNumber() {}
func (bitOr) ResolvesToInt()    {}
func (bitOr) ResolvesToLong()   {}

func (bo bitOr) MarshalBSONValue() (byte, []byte, error) {
	t, v, err := bson.MarshalValue(bo.expr)
	return byte(t), v, err
}

func BitOr(expr ResolvesToNumber) interface {
	ResolvesToInt
	ResolvesToLong
} {
	return bitOr{expr: bson.D{{Key: "$bitOr", Value: expr}}}
}

func Size(expression ResolvesToArray) ResolvesToInt {
	return resolvesToInt{
		expr: bson.D{{Key: "$size", Value: expression}},
	}
}

func ArrayToObject(array ResolvesToArray) ResolvesToObject {
	return resolvesToObject{
		expr: bson.D{{Key: "$arrayToObject", Value: array}},
	}
}

// TODO: How do we do optional params?
func Zip[T any](inputs []ResolvesToArray, useLongestLength bool, defaults []T) ResolvesToArray {
	return resolvesToArray{
		expr: bson.D{{Key: "$zip", Value: bson.D{
			{Key: "inputs", Value: inputs},
			{Key: "useLongestLength", Value: useLongestLength},
			{Key: "defaults", Value: defaults},
		}}},
	}
}

func MergeObjects(document ...ResolvesToObject) ResolvesToObject {
	return resolvesToObject{
		expr: bson.D{{Key: "$mergeObjects", Value: document}},
	}
}

func Filter(input ResolvesToArray, cond ResolvesToBool, as string) ResolvesToArray {
	return resolvesToArray{
		expr: bson.D{{Key: "$filter", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "cond", Value: cond},
			{Key: "as", Value: as},
		}}},
	}
}

func In(expression Expression, array ResolvesToArray) ResolvesToBool {
	return resolvesToBool{
		expr: bson.D{{Key: "$in", Value: bson.A{expression, array}}},
	}
}

func Map(input ResolvesToArray, as string, in Expression) ResolvesToArray {
	return resolvesToArray{
		expr: bson.D{{Key: "$map", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "as", Value: as},
			{Key: "in", Value: in},
		}}},
	}
}

func Reduce(input ResolvesToArray, initialValue Expression, in Expression) ResolvesToAny {
	return resolvesToAny{
		expr: bson.D{{Key: "$reduce", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "initialValue", Value: initialValue},
			{Key: "in", Value: in},
		}}},
	}
}
