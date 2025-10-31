package query

import "go.mongodb.org/mongo-driver/v2/bson"

type FieldQuery any

type Query struct {
	expr any
}

func Field(field string, query FieldQuery) Query {
	return Query{
		expr: bson.D{{Key: field, Value: query}},
	}
}

func Ne(value any) FieldQuery {
	return bson.D{{Key: "$ne", Value: value}}
}

func Gt(value any) FieldQuery {
	return bson.D{{Key: "$gt", Value: value}}
}

func And(queries ...Query) Query {
	return Query{
		expr: bson.D{{Key: "$and", Value: queries}},
	}
}
