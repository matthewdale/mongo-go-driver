package agg

import (
	"go.mongodb.org/mongo-driver/v2/bson"
)

type Number interface {
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

type SortSpec struct {
	Field string
	Order SortOrder
}

func SortStage[T Expression | SortSpec](sort ...T) Stage {
	return Stage{{Key: "$sort", Value: sort}}
}

type GroupField struct {
	Name        string
	Accumulator Accumulator
}

func GroupStage[T Expression | string](_id T, field ...GroupField) Stage {
	fields := make(bson.D, 0, len(field))
	fields = append(fields, bson.E{Key: "_id", Value: _id})
	for _, f := range field {
		fields = append(fields, bson.E{Key: f.Name, Value: f.Accumulator})
	}
	return Stage{{Key: "$group", Value: fields}}
}

type NamedExpression struct {
	Name       string
	Expression Expression
}

func SetStage(expression ...NamedExpression) Stage {
	doc := make(bson.D, 0, len(expression))
	for _, ne := range expression {
		doc = append(doc, bson.E{Key: ne.Name, Value: ne.Expression})
	}
	return Stage{{Key: "$set", Value: doc}}
}

func ProjectStage(specification ...NamedExpression) Stage {
	doc := make(bson.D, 0, len(specification))
	for _, ne := range specification {
		doc = append(doc, bson.E{Key: ne.Name, Value: ne.Expression})
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

func LastNAccumulator[T ResolvesToNumber | Number](input ResolvesToArray, n T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$lastN", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "n", Value: n},
		}}},
	}
}

func AvgAccumulator[T ResolvesToNumber | Number](expression T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$avg", Value: expression}},
	}
}

func SumAccumulator[T ResolvesToNumber | Number](expression T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$sum", Value: expression}},
	}
}

func MinAccumulator[T ResolvesToNumber | Number](expression T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$min", Value: expression}},
	}
}

func MaxAccumulator[T ResolvesToNumber | Number](expression T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$max", Value: expression}},
	}
}

func PercentileAccumulator[T ResolvesToNumber | Number, U ResolvesToArray | []float32 | []float64](input T, p U) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$percentile", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "p", Value: p},
			// TODO: Currently the method must always be "approximate". Do we need an argument for that?
			{Key: "method", Value: "approximate"},
		}}},
	}
}

// TODO: Is there a more constrained set of types we can use here?
type Expression any

type ResolvesToNumber struct {
	expr Expression
}

func (rtn ResolvesToNumber) MarshalBSONValue() (byte, []byte, error) {
	typ, b, err := bson.MarshalValue(rtn.expr)
	return byte(typ), b, err
}

func NumberFieldPath(field string) ResolvesToNumber {
	return ResolvesToNumber{
		expr: "$" + field,
	}
}

type ResolvesToArray struct {
	expr Expression
}

func (rta ResolvesToArray) MarshalBSONValue() (byte, []byte, error) {
	typ, b, err := bson.MarshalValue(rta.expr)
	return byte(typ), b, err
}

func ArrayFieldPath(field string) ResolvesToArray {
	return ResolvesToArray{
		expr: "$" + field,
	}
}

func Array[T any](values []T) ResolvesToArray {
	return ResolvesToArray{
		expr: values,
	}
}

type ResolvesToObject struct {
	expr Expression
}

func (rto ResolvesToObject) MarshalBSONValue() (byte, []byte, error) {
	typ, b, err := bson.MarshalValue(rto.expr)
	return byte(typ), b, err
}

func ObjectFieldPath(field string) ResolvesToObject {
	return ResolvesToObject{
		expr: "$" + field,
	}
}

func RootObject() ResolvesToObject {
	return ResolvesToObject{
		expr: "$$ROOT",
	}
}

type ResolvesToBool struct {
	expr Expression
}

func (rtb ResolvesToBool) MarshalBSONValue() (byte, []byte, error) {
	typ, b, err := bson.MarshalValue(rtb.expr)
	return byte(typ), b, err
}

func Abs[T ResolvesToNumber | Number](value T) ResolvesToNumber {
	return ResolvesToNumber{
		expr: bson.D{{Key: "$abs", Value: value}},
	}
}

func BitOr[T ResolvesToNumber | Number](expression T) ResolvesToNumber {
	return ResolvesToNumber{
		expr: bson.D{{Key: "$bitOr", Value: expression}},
	}
}

// TODO: How can we accept a slice of any type here? Is "Array" good enough?
func Size(expression ResolvesToArray) ResolvesToNumber {
	return ResolvesToNumber{
		expr: bson.D{{Key: "$size", Value: expression}},
	}
}

func ArrayToObject(array ResolvesToArray) ResolvesToObject {
	return ResolvesToObject{
		expr: bson.D{{Key: "$arrayToObject", Value: array}},
	}
}

// TODO: How do we do optional params?
func Zip[T any](inputs []ResolvesToArray, useLongestLength bool, defaults []T) ResolvesToArray {
	return ResolvesToArray{
		expr: bson.D{{Key: "$zip", Value: bson.D{
			{Key: "inputs", Value: inputs},
			{Key: "useLongestLength", Value: useLongestLength},
			{Key: "defaults", Value: defaults},
		}}},
	}
}

func MergeObjects(document ...ResolvesToObject) ResolvesToObject {
	return ResolvesToObject{
		expr: bson.D{{Key: "$mergeObjects", Value: document}},
	}
}

func Filter(input ResolvesToArray, cond ResolvesToBool, as string) ResolvesToArray {
	return ResolvesToArray{
		expr: bson.D{{Key: "$filter", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "cond", Value: cond},
			{Key: "as", Value: as},
		}}},
	}
}

func In(expression Expression, array ResolvesToArray) ResolvesToBool {
	return ResolvesToBool{
		expr: bson.D{{Key: "$in", Value: bson.A{expression, array}}},
	}
}
