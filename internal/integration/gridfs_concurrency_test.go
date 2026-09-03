// Copyright (C) MongoDB, Inc. 2017-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/internal/integration/mtest"
	"go.mongodb.org/mongo-driver/v2/internal/israce"
	"go.mongodb.org/mongo-driver/v2/internal/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestGridFSBucketConcurrency asserts that the exported methods of
// mongo.GridFSBucket are safe to call from multiple goroutines. A bucket is
// handed out by (*Database).GridFSBucket and is naturally treated by users as a
// long-lived, shareable handle, like *Collection and *Client.
//
// There is one subtest per exported method, each calling only that method from
// many goroutines against a shared bucket. Correctness of the transferred bytes
// is covered by TestGridFS; what these subtests assert is the absence of data
// races, so they must be run with -race:
//
//	go test -race -run TestGridFSBucketConcurrency ./internal/integration/
//
// The upload subtests fail today and are skipped with a reference to
// GODRIVER-3841. GridFSBucket has two fields that are mutated after
// construction and guarded by nothing: firstWriteDone, an unsynchronized
// check-then-set on every upload path, and readBuf, a single scratch buffer
// reused by every UploadFromStream/UploadFromStreamWithID call. Remove the
// skips to reproduce, and delete them once the bucket is goroutine-safe.
//
// Concurrent use of an individual GridFSUploadStream or GridFSDownloadStream is
// out of scope: those remain single-goroutine, consistent with the io.Reader
// and io.Writer conventions. Every subtest below gives each goroutine its own
// stream and shares only the bucket.
func TestGridFSBucketConcurrency(x *testing.T) {
	mt := mtest.New(x, noClientOpts)

	// chunkSizeBytes is deliberately small so that each upload and download
	// spans several chunks and makes repeated passes over the bucket's internal
	// state rather than completing in a single operation.
	const chunkSizeBytes int32 = 4096

	// Both values are tuned for how reliably the race detector catches the
	// known GODRIVER-3841 races, measured by unskipping the upload subtests and
	// re-running them.
	//
	// A bucket serializes its own one-time setup after the first write, so each
	// round offers only one window in which the racing accesses can overlap.
	// rounds reopens that window on a fresh bucket. goroutines is the more
	// effective lever of the two: at 16 each upload subtest caught its race in
	// about half of runs no matter how many rounds it ran, while at 64 all four
	// caught it in every run. Lowering either weakens the test into a flaky one.
	goroutines, rounds := 64, 2

	timeout := 60 * time.Second
	if israce.Enabled {
		timeout = 180 * time.Second
	}

	payload := bytes.Repeat([]byte("mongodb"), int(chunkSizeBytes)/2)

	filenameFor := func(i int) string {
		return fmt.Sprintf("concurrent-file-%d", i)
	}

	// forEachRound runs body once per round against a bucket that is fresh but
	// backed by the same collections.
	forEachRound := func(mt *mtest.T, name string, body func(*mongo.GridFSBucket, context.Context)) {
		mt.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		mt.Cleanup(cancel)

		for round := 0; round < rounds; round++ {
			bucket := mt.DB.GridFSBucket(options.GridFSBucket().
				SetName(fmt.Sprintf("%s_%d", name, round)).
				SetChunkSizeBytes(chunkSizeBytes))

			body(bucket, ctx)
		}
	}

	// run calls fn concurrently, once per goroutine, and fails the test if any
	// call returns an error. fn must not call mt.Fatal, require.* or t.Skip:
	// the testing package forbids those from a spawned goroutine, so errors are
	// returned and reported here instead.
	run := func(mt *mtest.T, fn func(i int) error) {
		mt.Helper()

		// ready is a start barrier. Without it the goroutines trickle in as
		// errgroup schedules them, and the first call routinely finishes the
		// bucket's one-time setup before the rest begin, so the race detector
		// never sees the accesses overlap. Releasing them together is what
		// makes the detection reliable rather than sporadic.
		var ready sync.WaitGroup
		ready.Add(goroutines)

		var g errgroup.Group
		for i := 0; i < goroutines; i++ {
			g.Go(func() error {
				ready.Done()
				ready.Wait()

				return fn(i)
			})
		}

		require.NoError(mt, g.Wait(), "concurrent calls returned an error")
	}

	// seed uploads one file per goroutine serially, so the read-side subtests
	// have known-good files to work against, and returns their IDs.
	seed := func(mt *mtest.T, ctx context.Context, bucket *mongo.GridFSBucket) []bson.ObjectID {
		mt.Helper()

		fileIDs := make([]bson.ObjectID, goroutines)
		for i := range fileIDs {
			fileID, err := bucket.UploadFromStream(ctx, filenameFor(i), bytes.NewReader(payload))
			require.NoError(mt, err, "UploadFromStream error: %v", err)

			fileIDs[i] = fileID
		}

		return fileIDs
	}

	const uploadSkip = "GODRIVER-3841: GridFSBucket is not safe for concurrent uploads; " +
		"it races on firstWriteDone and shares a single readBuf. Unskip when the bucket is goroutine-safe."

	mt.Run("OpenUploadStream", func(mt *mtest.T) {
		mt.Skip(uploadSkip)

		forEachRound(mt, "concurrent_open_upload_stream", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			run(mt, func(i int) error {
				us, err := bucket.OpenUploadStream(ctx, filenameFor(i))
				if err != nil {
					return fmt.Errorf("OpenUploadStream error: %w", err)
				}

				if _, err := us.Write(payload); err != nil {
					_ = us.Abort()

					return fmt.Errorf("Write error: %w", err)
				}

				return us.Close()
			})
		})
	})

	mt.Run("OpenUploadStreamWithID", func(mt *mtest.T) {
		mt.Skip(uploadSkip)

		forEachRound(mt, "concurrent_open_upload_stream_with_id", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			run(mt, func(i int) error {
				us, err := bucket.OpenUploadStreamWithID(ctx, bson.NewObjectID(), filenameFor(i))
				if err != nil {
					return fmt.Errorf("OpenUploadStreamWithID error: %w", err)
				}

				if _, err := us.Write(payload); err != nil {
					_ = us.Abort()

					return fmt.Errorf("Write error: %w", err)
				}

				return us.Close()
			})
		})
	})

	mt.Run("UploadFromStream", func(mt *mtest.T) {
		mt.Skip(uploadSkip)

		forEachRound(mt, "concurrent_upload_from_stream", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			run(mt, func(i int) error {
				_, err := bucket.UploadFromStream(ctx, filenameFor(i), bytes.NewReader(payload))

				return err
			})
		})
	})

	mt.Run("UploadFromStreamWithID", func(mt *mtest.T) {
		mt.Skip(uploadSkip)

		forEachRound(mt, "concurrent_upload_from_stream_with_id", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			run(mt, func(i int) error {
				return bucket.UploadFromStreamWithID(ctx, bson.NewObjectID(), filenameFor(i),
					bytes.NewReader(payload))
			})
		})
	})

	mt.Run("OpenDownloadStream", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_open_download_stream", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			fileIDs := seed(mt, ctx, bucket)

			run(mt, func(i int) error {
				ds, err := bucket.OpenDownloadStream(ctx, fileIDs[i])
				if err != nil {
					return fmt.Errorf("OpenDownloadStream error: %w", err)
				}

				if _, err := io.Copy(io.Discard, ds); err != nil {
					_ = ds.Close()

					return fmt.Errorf("read error: %w", err)
				}

				return ds.Close()
			})
		})
	})

	mt.Run("OpenDownloadStreamByName", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_open_download_stream_by_name", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			seed(mt, ctx, bucket)

			run(mt, func(i int) error {
				ds, err := bucket.OpenDownloadStreamByName(ctx, filenameFor(i))
				if err != nil {
					return fmt.Errorf("OpenDownloadStreamByName error: %w", err)
				}

				if _, err := io.Copy(io.Discard, ds); err != nil {
					_ = ds.Close()

					return fmt.Errorf("read error: %w", err)
				}

				return ds.Close()
			})
		})
	})

	mt.Run("DownloadToStream", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_download_to_stream", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			fileIDs := seed(mt, ctx, bucket)

			run(mt, func(i int) error {
				_, err := bucket.DownloadToStream(ctx, fileIDs[i], io.Discard)

				return err
			})
		})
	})

	mt.Run("DownloadToStreamByName", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_download_to_stream_by_name", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			seed(mt, ctx, bucket)

			run(mt, func(i int) error {
				_, err := bucket.DownloadToStreamByName(ctx, filenameFor(i), io.Discard)

				return err
			})
		})
	})

	mt.Run("Find", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_find", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			seed(mt, ctx, bucket)

			run(mt, func(i int) error {
				cursor, err := bucket.Find(ctx, bson.D{{"filename", filenameFor(i)}})
				if err != nil {
					return fmt.Errorf("Find error: %w", err)
				}
				defer func() { _ = cursor.Close(ctx) }()

				var files []bson.Raw
				if err := cursor.All(ctx, &files); err != nil {
					return fmt.Errorf("cursor All error: %w", err)
				}

				return nil
			})
		})
	})

	mt.Run("Delete", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_delete", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			fileIDs := seed(mt, ctx, bucket)

			// Each goroutine deletes only its own file, so no call should observe a
			// file another goroutine already removed.
			run(mt, func(i int) error {
				return bucket.Delete(ctx, fileIDs[i])
			})
		})
	})

	mt.Run("Rename", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_rename", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			fileIDs := seed(mt, ctx, bucket)

			run(mt, func(i int) error {
				return bucket.Rename(ctx, fileIDs[i], filenameFor(i)+"-renamed")
			})
		})
	})

	mt.Run("Drop", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_drop", func(bucket *mongo.GridFSBucket, ctx context.Context) {
			seed(mt, ctx, bucket)

			// Dropping an already-dropped bucket is a no-op, so every overlapping
			// call must still succeed.
			run(mt, func(int) error {
				return bucket.Drop(ctx)
			})
		})
	})

	mt.Run("GetFilesCollection", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_get_files_collection", func(bucket *mongo.GridFSBucket, _ context.Context) {
			run(mt, func(int) error {
				if coll := bucket.GetFilesCollection(); coll == nil {
					return errors.New("GetFilesCollection returned nil")
				}

				return nil
			})
		})
	})

	mt.Run("GetChunksCollection", func(mt *mtest.T) {
		forEachRound(mt, "concurrent_get_chunks_collection", func(bucket *mongo.GridFSBucket, _ context.Context) {
			run(mt, func(int) error {
				if coll := bucket.GetChunksCollection(); coll == nil {
					return errors.New("GetChunksCollection returned nil")
				}

				return nil
			})
		})
	})
}
