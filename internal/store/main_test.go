package store

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/kcansari/mixo/ent"
	_ "github.com/kcansari/mixo/ent/runtime" // registers soft-delete hooks/interceptors
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// testClient is a single ent.Client backed by one throwaway Postgres container
// shared by every test in this package. It is created in TestMain.
var testClient *ent.Client

// TestMain spins up a real Postgres in a Docker container once for the whole
// package, runs the ent schema migration against it, executes the tests, and
// then tears everything down. This is the standard testcontainers pattern:
// one container per package keeps the test run fast while still exercising the
// exact database engine used in production.
func TestMain(m *testing.M) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:18.4-alpine3.23",
		postgres.WithDatabase("mixo_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("store_test: starting postgres container: %v", err)
	}

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("store_test: building connection string: %v", err)
	}

	testClient, err = ent.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("store_test: opening ent client: %v", err)
	}

	if err := testClient.Schema.Create(ctx); err != nil {
		log.Fatalf("store_test: migrating schema: %v", err)
	}

	code := m.Run()

	// Best-effort cleanup before exiting. os.Exit does not run deferred calls,
	// so we close explicitly here.
	_ = testClient.Close()
	_ = pgContainer.Terminate(ctx)

	os.Exit(code)
}

// resetUsers hard-deletes every row in the users table so each test starts from
// a clean slate.
//
// Because all tests share one database, this reset means the top-level Test
// functions must run serially (no t.Parallel at the package level). The
// table-driven subtests inside each function also run serially for the same
// reason. If we wanted parallelism we would instead isolate state per test
// (e.g. a unique schema or unique emails per case) rather than truncating.
func resetUsers(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := testClient.User.Delete().Exec(ctx); err != nil {
		t.Fatalf("resetUsers: %v", err)
	}
}
