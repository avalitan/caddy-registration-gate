package registrationgate

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testScope = storeScope{anchor: "managed", namespace: "test"}

func TestDesiredStorePersistsAndExposesLeases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state?#.db")
	ctx := t.Context()

	func() {
		store, err := openDesiredStore(path, testScope)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Destruct()

		execStoreSQL(t, ctx, store.db, `
INSERT INTO principals VALUES ('p1', 'active', 100, NULL);
INSERT INTO services(name, owner_principal_id, service_type, mode, listener_name, revision)
VALUES ('site', 'p1', 'http', 'shared', 'https', 1);
INSERT INTO backends VALUES ('site', 'one', 'p1', 'explicit', '192.0.2.1', 8080, 'active');
INSERT INTO leases VALUES ('site', 'one', 'p1', 200, 100, 'default');
INSERT INTO leases VALUES ('site', NULL, 'p1', 300, 100, 'default');`)

		for _, statement := range []string{
			"INSERT INTO leases VALUES ('site', NULL, 'p1', 400, 100, 'default')",
			"INSERT INTO leases VALUES ('site', 'missing', 'p1', 400, 100, 'default')",
			"INSERT INTO leases VALUES ('site', 'one', 'p1', 400, 100, 'default')",
		} {
			if _, err := store.db.ExecContext(ctx, statement); err == nil {
				t.Fatalf("accepted invalid lease: %s", statement)
			}
		}
		if duplicate, err := openDesiredStore(path, testScope); err == nil {
			duplicate.Destruct()
			t.Fatal("opened a second writer")
		}

		for _, filename := range []string{path, path + "-wal", path + "-shm", path + ".writer.lock"} {
			info, err := os.Stat(filename)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("%s has mode %04o, want 0600", filename, info.Mode().Perm())
			}
		}

		uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro"}
		reader, err := sql.Open("sqlite", uri.String())
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		assertStoreValue(t, ctx, reader, "SELECT count(*) FROM lease_diagnostics", 2)
		if _, err := reader.ExecContext(ctx, "DELETE FROM leases"); err == nil {
			t.Fatal("read-only diagnostic connection wrote to the store")
		}
	}()

	store, err := openDesiredStore(path, testScope)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Destruct()
	assertStoreValue(t, ctx, store.db, "PRAGMA application_id", storeApplicationID)
	assertStoreValue(t, ctx, store.db, "PRAGMA user_version", len(storeMigrations))
	assertStoreValue(t, ctx, store.db, "SELECT expires_at FROM lease_diagnostics WHERE backend_name = 'one'", 200)
	execStoreSQL(t, ctx, store.db, "DELETE FROM backends WHERE service_name = 'site' AND instance_name = 'one'")
	assertStoreValue(t, ctx, store.db, "SELECT count(*) FROM lease_diagnostics WHERE backend_name IS NULL", 1)
	assertStoreValue(t, ctx, store.db, "SELECT count(*) FROM lease_diagnostics WHERE backend_name IS NOT NULL", 0)
}

func TestDesiredStoreRejectsIncompatibleDatabases(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup string
		want  string
	}{
		{"legacy", "CREATE TABLE leases(cn TEXT); INSERT INTO leases VALUES ('legacy'); PRAGMA user_version = 1", "not a Registration Gate database"},
		{"unversioned", "CREATE TABLE unrelated(id INTEGER)", "unrecognized SQLite database"},
		{"future", "PRAGMA application_id = 1129465159; PRAGMA user_version = 999", "newer than supported"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "existing.db")
			if err := ensureStoreFile(path); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			execStoreSQL(t, t.Context(), db, tt.setup)
			if store, err := openDesiredStore(path, testScope); err == nil {
				store.Destruct()
				t.Fatal("opened an incompatible database")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("open error %v, expected %q", err, tt.want)
			}
			assertStoreValue(t, t.Context(), db, "SELECT count(*) FROM sqlite_schema WHERE name = 'store_scope'", 0)
			if tt.name == "legacy" {
				assertStoreValue(t, t.Context(), db, "SELECT count(*) FROM leases WHERE cn = 'legacy'", 1)
			}
		})
	}
}

func execStoreSQL(t *testing.T, ctx context.Context, db *sql.DB, statement string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, statement); err != nil {
		t.Fatal(err)
	}
}

func assertStoreValue(t *testing.T, ctx context.Context, db *sql.DB, query string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(ctx, query).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s returned %d, want %d", query, got, want)
	}
}
