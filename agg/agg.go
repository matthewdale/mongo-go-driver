package agg

import (
	"go.mongodb.org/mongo-driver/v2/bson"
)

type Number interface {
	~int8 | ~int16 | ~int32 | ~int64 | ~int |
		~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uint | ~uintptr |
		~float32 | ~float64
}

type ArrayTypes interface {
	ResolvesToAny | ResolvesToArray | string
}

type NumberTypes interface {
	ResolvesToAny | ResolvesToNumber | Number | string
}

type StringTypes interface {
	ResolvesToAny | ResolvesToString | string
}

type BoolTypes interface {
	ResolvesToAny | ResolvesToBool | bool
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

func SortStage[T SortSpec | Expression](sort ...T) Stage {
	return Stage{{Key: "$sort", Value: sort}}
}

type GroupKey []struct {
	Name       string
	Expression Expression
}

type GroupField struct {
	Name        string
	Accumulator Accumulator
}

func GroupStage[T GroupKey | Expression | string](_id T, field ...GroupField) Stage {
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

func LastNAccumulator[T NumberTypes](input ResolvesToArray, n T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$lastN", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "n", Value: n},
		}}},
	}
}

func AvgAccumulator[T NumberTypes](expr T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$avg", Value: expr}},
	}
}

func SumAccumulator[T NumberTypes](expr T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$sum", Value: expr}},
	}
}

func MinAccumulator[T NumberTypes](expr T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$min", Value: expr}},
	}
}

func MaxAccumulator[T NumberTypes](expr T) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$max", Value: expr}},
	}
}

func PercentileAccumulator[T NumberTypes, U ArrayTypes | []float32 | []float64](input T, p U) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$percentile", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "p", Value: p},
			// TODO: Currently the method must always be "approximate". Do we need an argument for that?
			{Key: "method", Value: "approximate"},
		}}},
	}
}

func PushAccumulator(expr Expression) Accumulator {
	return Accumulator{
		doc: bson.D{{Key: "$push", Value: expr}},
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

func NumberField(fieldPath string) ResolvesToNumber {
	return ResolvesToNumber{
		expr: fieldPath,
	}
}

type ResolvesToArray struct {
	expr Expression
}

func (rta ResolvesToArray) MarshalBSONValue() (byte, []byte, error) {
	typ, b, err := bson.MarshalValue(rta.expr)
	return byte(typ), b, err
}

func ArrayField(fieldPath string) ResolvesToArray {
	return ResolvesToArray{
		expr: fieldPath,
	}
}

func Array[T any](values []T) ResolvesToArray {
	return ResolvesToArray{
		expr: values,
	}
}

type ResolvesToString struct {
	expr Expression
}

func (rts ResolvesToString) MarshalBSONValue() (byte, []byte, error) {
	typ, b, err := bson.MarshalValue(rts.expr)
	return byte(typ), b, err
}

type ResolvesToAny struct {
	expr Expression
}

func (rta ResolvesToAny) MarshalBSONValue() (byte, []byte, error) {
	typ, b, err := bson.MarshalValue(rta.expr)
	return byte(typ), b, err
}

type ResolvesToObject struct {
	expr Expression
}

func (rto ResolvesToObject) MarshalBSONValue() (byte, []byte, error) {
	typ, b, err := bson.MarshalValue(rto.expr)
	return byte(typ), b, err
}

func ObjectField(fieldPath string) ResolvesToObject {
	return ResolvesToObject{
		expr: fieldPath,
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

func Abs[T NumberTypes](value T) ResolvesToNumber {
	return ResolvesToNumber{
		expr: bson.D{{Key: "$abs", Value: value}},
	}
}

func BitOr[T NumberTypes](expr T) ResolvesToNumber {
	return ResolvesToNumber{
		expr: bson.D{{Key: "$bitOr", Value: expr}},
	}
}

// TODO: How can we accept a slice of any type here? Is "Array" good enough?
func Size[T ArrayTypes](expr T) ResolvesToNumber {
	return ResolvesToNumber{
		expr: bson.D{{Key: "$size", Value: expr}},
	}
}

func ArrayToObject[T ArrayTypes](array T) ResolvesToObject {
	return ResolvesToObject{
		expr: bson.D{{Key: "$arrayToObject", Value: array}},
	}
}

// TODO: How do we do optional params?
func Zip[T ArrayTypes, U any](inputs []T, useLongestLength bool, defaults []U) ResolvesToArray {
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

func Filter[T ArrayTypes, U BoolTypes](input T, cond U, as string) ResolvesToArray {
	return ResolvesToArray{
		expr: bson.D{{Key: "$filter", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "cond", Value: cond},
			{Key: "as", Value: as},
		}}},
	}
}

func In[T ArrayTypes](expr Expression, array T) ResolvesToBool {
	return ResolvesToBool{
		expr: bson.D{{Key: "$in", Value: bson.A{expr, array}}},
	}
}

func AnyElementTrue[T ArrayTypes](array T) ResolvesToBool {
	return ResolvesToBool{
		expr: bson.D{{Key: "$anyElementTrue", Value: array}},
	}
}

func Add[T NumberTypes](values ...T) ResolvesToNumber {
	return ResolvesToNumber{
		expr: bson.D{{Key: "$add", Value: values}},
	}
}

func Multiply[T NumberTypes](values ...T) ResolvesToNumber {
	return ResolvesToNumber{
		expr: bson.D{{Key: "$multiply", Value: values}},
	}
}

func Map[T ArrayTypes, U StringTypes](input T, as U, in Expression) ResolvesToArray {
	return ResolvesToArray{
		expr: bson.D{{Key: "$map", Value: bson.D{
			{Key: "input", Value: input},
			{Key: "as", Value: as},
			{Key: "in", Value: in},
		}}},
	}
}

func Reduce[T ArrayTypes](input T, initialValue Expression, in Expression) Expression {
	return bson.D{{Key: "$reduce", Value: bson.D{
		{Key: "input", Value: input},
		{Key: "initialValue", Value: initialValue},
		{Key: "in", Value: in},
	}}}
}

type TruncOption func(*ResolvesToNumber)

func TruncPlace[T NumberTypes](place T) TruncOption {
	return func(rtn *ResolvesToNumber) {
		rtn.expr.(bson.D)[0].Value = append(rtn.expr.(bson.D)[0].Value.(bson.A), place)
	}
}

func Trunc[T NumberTypes, U NumberTypes](number T, opts ...TruncOption) ResolvesToNumber {
	rtn := ResolvesToNumber{
		expr: bson.D{{Key: "$trunc", Value: bson.A{number}}},
	}
	for _, opt := range opts {
		opt(&rtn)
	}
	return rtn
}

func ConcatArrays[T ArrayTypes](arrays ...T) ResolvesToArray {
	return ResolvesToArray{
		expr: bson.D{{Key: "$concatArrays", Value: arrays}},
	}
}
