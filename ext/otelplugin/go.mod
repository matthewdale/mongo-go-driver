module go.mongodb.org/mongo-driver/ext/otelplugin

go 1.26.4

require (
	go.mongodb.org/mongo-driver/v2 v2.8.0
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/trace v1.45.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
)

replace go.mongodb.org/mongo-driver/v2 => ../../
