package registrationgate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/gofrs/flock"
	_ "modernc.org/sqlite"
)

// Caddy starts the incoming configuration before stopping the outgoing one.
// Share the managed anchor's writer and its process lock during reload.
var desiredStores = caddy.NewUsagePool()

var errStoreScope = errors.New("database belongs to a different managed anchor or namespace")

type storeScope struct {
	anchor    string
	namespace string
}

type desiredStore struct {
	path  string
	scope storeScope
	db    *sql.DB
	lock  *flock.Flock
}

func prepareStorePath(path string) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("database directory must not be writable by group or others")
	}
	return filepath.Join(dir, filepath.Base(path)), nil
}

// Pre-create private files so their permissions don't depend on the SQLite VFS
// default or the process umask. A pre-provisioned 0640 file permits group reads.
func ensureStoreFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		return errors.Join(f.Chmod(0o600), f.Close())
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	perm := info.Mode().Perm()
	if !info.Mode().IsRegular() || perm&0o600 != 0o600 || perm&^0o640 != 0 {
		return fmt.Errorf("%q must be a regular file with mode 0600 or 0640", path)
	}
	return nil
}

func openDesiredStore(path string, scope storeScope) (_ *desiredStore, err error) {
	lockPath := path + ".writer.lock"
	if err := ensureStoreFile(lockPath); err != nil {
		return nil, err
	}
	lock := flock.New(lockPath)
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("another process owns the registration database writer")
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	if err := ensureStoreFile(path); err != nil {
		return nil, err
	}

	query := url.Values{
		"mode":    {"rw"},
		"_txlock": {"immediate"},
		"_pragma": {"busy_timeout(5000)", "foreign_keys(ON)", "trusted_schema(OFF)", "synchronous(FULL)"},
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query.Encode()}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, db.Close())
		}
	}()
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrateStore(ctx, db, scope); err != nil {
		return nil, err
	}
	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&journal); err != nil {
		return nil, fmt.Errorf("enable SQLite WAL: %w", err)
	}
	if journal != "wal" {
		return nil, fmt.Errorf("SQLite returned journal mode %q, expected wal", journal)
	}
	// Open the WAL and shared-memory files so explicitly authorized read-only
	// tools can attach even before the first registration writes to SQLite.
	var singleton int
	if err := db.QueryRowContext(ctx, "SELECT singleton FROM store_scope").Scan(&singleton); err != nil {
		return nil, fmt.Errorf("initialize SQLite WAL reader state: %w", err)
	}
	return &desiredStore{path: path, scope: scope, db: db, lock: lock}, nil
}

func (s *desiredStore) Destruct() error {
	return errors.Join(s.db.Close(), s.lock.Close())
}
