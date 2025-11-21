package agg_test

import (
	"bytes"
	"fmt"
	"testing"

	"go.mongodb.org/mongo-driver/v2/agg"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func Example() {
	pipeline := agg.Pipeline{
		agg.SortStage(
			agg.SortSpec{
				Field: "score",
				Order: agg.SortTextScore,
			},
			agg.SortSpec{
				Field: "blah",
				Order: agg.SortDescending,
			}),
	}

	agg.ProjectStage(
		agg.NamedExpression{
			Name: "distanceValues",
			Expression: agg.Reduce(
				agg.Map("$distances", "decimalValue", agg.Trunc("$$decimalValue", 0)),
				0,
				agg.ConcatArrays("$$value", "$$this"),
			),
		},
		agg.NamedExpression{
			Name:       "integerValues",
			Expression: agg.Map("$distances", "decimalValue", "$$decimalValue"),
		})

	agg.GroupStage(
		agg.GroupKey{
			{"timestamp", "$timestamp"},
			{"storage_system_id", "$storage_system_id"},
			{"name", "$name"},
		},
		agg.GroupField{"blah", agg.AvgAccumulator("blah")},
	)

	b, err := bson.Marshal(pipeline)
	if err != nil {
		panic(err)
	}
	fmt.Println(bson.Raw(b))
	// Output: blah
}

// Recreate the example aggregation pipeline from
// https://github.com/alcaeus/fupran-doctrine/blob/f0f1e0f0b308485acd40fcdfea5d62ad339619f8/src/Aggregation/PriceReport.php#L155
//
// public static function computeAggregates(stdClass $group): Pipeline
//
//	{
//		$percentiles = [
//			'p50' => 0.5,
//			'p90' => 0.9,
//			'p95' => 0.95,
//			'p99' => 0.99,
//		];
//
//		return new Pipeline(
//			Stage::group(
//				_id: $group,
//				numChanges: Accumulator::avg(Expression::size(Expression::arrayFieldPath('prices'))),
//				lowestPrice: Accumulator::min(Expression::doubleFieldPath('lowestPrice.price')),
//				highestPrice: Accumulator::max(Expression::doubleFieldPath('highestPrice.price')),
//				weightedAveragePrice: Accumulator::avg(Expression::doubleFieldPath('weightedAveragePrice')),
//				percentiles: Accumulator::percentile(
//					input: Expression::doubleFieldPath('weightedAveragePrice'),
//					p: array_values($percentiles),
//					method: 'approximate',
//				),
//			),
//			Stage::set(
//				percentiles: Expression::arrayToObject(
//					Expression::zip([
//						array_keys($percentiles),
//						Expression::arrayFieldPath('percentiles'),
//					]),
//				),
//			),
//			Stage::replaceWith(Expression::mergeObjects(
//				Expression::fieldPath('_id'),
//				Expression::variable('ROOT'),
//			)),
//			Stage::unset('_id'),
//		);
//	}
func Test_computeAggregates(t *testing.T) {
	percentiles := []float64{0.5, 0.9, 0.95, 0.99}

	pipeline := agg.Pipeline{
		agg.GroupStage(
			"field",
			agg.GroupField{
				Name:        "numChanges",
				Accumulator: agg.AvgAccumulator(agg.Size("$prices")),
			},
			agg.GroupField{
				Name:        "lowestPrice",
				Accumulator: agg.MinAccumulator("$prices.price"),
			},
			agg.GroupField{
				Name:        "highestPrice",
				Accumulator: agg.MaxAccumulator("$prices.price"),
			},
			agg.GroupField{
				Name:        "weightedAveragePrice",
				Accumulator: agg.AvgAccumulator("$weightedAveragePrice"),
			},
			agg.GroupField{
				Name:        "percentiles",
				Accumulator: agg.PercentileAccumulator("$weightedAveragePrice", percentiles),
			},
		),
		agg.SetStage(agg.NamedExpression{
			Name: "percentiles",
			Expression: agg.ArrayToObject(agg.Zip(
				[]agg.ResolvesToArray{
					agg.Array(percentiles),
					agg.ArrayField("$percentiles"),
				},
				true,
				[]float64{},
			)),
		}),
		agg.ReplaceWithStage(
			agg.MergeObjects(
				agg.ObjectField("$_id"),
				agg.RootObject())),
		agg.UnsetStage("_id"),
	}

	got, err := bson.Marshal(pipeline)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	want, err := bson.Marshal(bson.D{{Key: "pipeline", Value: bson.A{
		bson.D{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "field"},
				{Key: "numChanges", Value: bson.D{{Key: "$avg", Value: bson.D{{Key: "$size", Value: "$prices"}}}}},
				{Key: "lowestPrice", Value: bson.D{{Key: "$min", Value: "$prices.price"}}},
				{Key: "highestPrice", Value: bson.D{{Key: "$max", Value: "$prices.price"}}},
				{Key: "weightedAveragePrice", Value: bson.D{{Key: "$avg", Value: "$weightedAveragePrice"}}},
				{Key: "percentiles", Value: bson.D{{Key: "$percentile", Value: bson.D{
					{Key: "input", Value: "$weightedAveragePrice"},
					{Key: "p", Value: bson.A{0.5, 0.9, 0.95, 0.99}},
					{Key: "method", Value: "approximate"},
				}}}},
			}}},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "percentiles", Value: bson.D{
					{Key: "$arrayToObject", Value: bson.D{
						{Key: "$zip", Value: bson.D{
							{Key: "inputs", Value: bson.A{
								bson.A{0.5, 0.9, 0.95, 0.99},
								"$percentiles",
							}},
							{Key: "useLongestLength", Value: true},
							{Key: "defaults", Value: bson.A{}},
						}},
					}},
				}},
			}}},
		bson.D{
			{Key: "$replaceWith", Value: bson.D{
				{Key: "$mergeObjects", Value: bson.A{
					"$_id",
					"$$ROOT",
				}},
			}}},
		bson.D{
			{Key: "$unset", Value: bson.A{"_id"}},
		},
	}}})
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	if !bytes.Equal(want, got) {
		t.Errorf(
			"Pipelines don't match.\nWant: %s\nGot:  %s",
			bson.Raw(want).String(),
			bson.Raw(got).String())
	}
}

func Test_mapReduce(t *testing.T) {
	pipeline := agg.Pipeline{
		agg.ProjectStage(
			agg.NamedExpression{
				Name: "distanceValues",
				Expression: agg.Reduce(
					agg.Map("$distances", "decimalValue", agg.Trunc("$$decimalValue", 0)),
					0,
					agg.ConcatArrays("$$value", "$$this"),
				),
			}),
	}
	got, err := bson.Marshal(pipeline)
	if err != nil {
		panic(err)
	}

	want, err := bson.Marshal(bson.D{
		{"pipeline", bson.A{
			bson.D{
				{"$project", bson.D{
					{"distanceValues", bson.D{
						{"$reduce", bson.D{
							{"input", bson.D{
								{"$map", bson.D{
									{"input", "$distances"},
									{"as", "decimalValue"},
									{"in", bson.D{
										{"$trunc", bson.A{"$$decimalValue", 0}},
									}},
								}},
							}},
							{"initialValue", 0},
							{"in", bson.D{
								{"$concatArrays", bson.A{"$$value", "$$this"}},
							}},
						}},
					}},
				}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	if !bytes.Equal(want, got) {
		t.Errorf(
			"Pipelines don't match.\nWant: %s\nGot:  %s",
			bson.Raw(want).String(),
			bson.Raw(got).String())
	}
}
