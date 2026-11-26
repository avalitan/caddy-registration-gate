package registrationgate

import (
	"context"
	"database/sql"
	"fmt"
)

// The application ID identifies a Registration Gate store independently of
// user_version, which is also used by the legacy SQLite Leases module.
const storeApplicationID = 0x43524547 // CREG

// Keep each released migration intact. Append later changes so that an older
// store can be upgraded in one transaction without losing existing state.
var storeMigrations = []string{`
CREATE TABLE store_scope (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    managed_anchor TEXT NOT NULL,
    namespace TEXT NOT NULL
) STRICT;

CREATE TABLE trust_domains (
    name TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
) STRICT;

CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at INTEGER NOT NULL,
    disabled_at INTEGER
) STRICT;

CREATE TABLE credentials (
    trust_domain TEXT NOT NULL REFERENCES trust_domains(name),
    spki_sha256 BLOB NOT NULL CHECK (length(spki_sha256) = 32),
    principal_id TEXT NOT NULL REFERENCES principals(id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked', 'retired')),
    enrolled_at INTEGER NOT NULL,
    retired_at INTEGER,
    PRIMARY KEY (trust_domain, spki_sha256)
) STRICT;
CREATE INDEX credentials_by_principal ON credentials(principal_id);

CREATE TABLE certificate_authorizations (
    trust_domain TEXT NOT NULL,
    spki_sha256 BLOB NOT NULL,
    certificate_sha256 BLOB NOT NULL CHECK (length(certificate_sha256) = 32),
    scope_kind TEXT NOT NULL,
    scope_name TEXT NOT NULL,
    authorized_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (trust_domain, spki_sha256, certificate_sha256, scope_kind, scope_name),
    FOREIGN KEY (trust_domain, spki_sha256) REFERENCES credentials(trust_domain, spki_sha256)
) STRICT;
CREATE INDEX certificate_authorizations_by_fingerprint ON certificate_authorizations(certificate_sha256);

CREATE TABLE capability_policies (
    scope_kind TEXT NOT NULL,
    scope_name TEXT NOT NULL,
    capability TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    identity_mode TEXT CHECK (identity_mode IN ('spki', 'certificate')),
    PRIMARY KEY (scope_kind, scope_name, capability)
) STRICT;

CREATE TABLE services (
    name TEXT PRIMARY KEY,
    owner_principal_id TEXT NOT NULL REFERENCES principals(id),
    service_type TEXT NOT NULL CHECK (service_type IN ('http', 'tcp')),
    mode TEXT NOT NULL CHECK (mode IN ('independent', 'shared')),
    listener_name TEXT NOT NULL,
    hostname TEXT,
    empty_policy TEXT NOT NULL DEFAULT 'unavailable' CHECK (empty_policy IN ('delete', 'retain', 'unavailable')),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;
CREATE INDEX services_by_owner ON services(owner_principal_id);

CREATE TABLE backends (
    service_name TEXT NOT NULL REFERENCES services(name) ON DELETE CASCADE,
    instance_name TEXT NOT NULL,
    owner_principal_id TEXT NOT NULL REFERENCES principals(id),
    address_source TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER CHECK (port BETWEEN 1 AND 65535),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    PRIMARY KEY (service_name, instance_name)
) STRICT;
CREATE INDEX backends_by_owner ON backends(owner_principal_id);

-- All timestamps are Unix seconds in UTC. A NULL backend identifies a service lease.
CREATE TABLE leases (
    service_name TEXT NOT NULL REFERENCES services(name) ON DELETE CASCADE,
    backend_name TEXT,
    renewer_principal_id TEXT NOT NULL REFERENCES principals(id),
    expires_at INTEGER NOT NULL,
    last_heartbeat_at INTEGER NOT NULL,
    policy TEXT NOT NULL,
    FOREIGN KEY (service_name, backend_name) REFERENCES backends(service_name, instance_name) ON DELETE CASCADE,
    CHECK (expires_at >= last_heartbeat_at)
) STRICT;
CREATE UNIQUE INDEX service_leases_by_resource ON leases(service_name) WHERE backend_name IS NULL;
CREATE UNIQUE INDEX backend_leases_by_resource ON leases(service_name, backend_name) WHERE backend_name IS NOT NULL;
CREATE INDEX leases_by_expiry ON leases(expires_at);
CREATE INDEX leases_by_renewer ON leases(renewer_principal_id);

CREATE VIEW lease_diagnostics AS
SELECT service_name, backend_name, expires_at, last_heartbeat_at, policy FROM leases;
`}

func migrateStore(ctx context.Context, db *sql.DB, scope storeScope) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var applicationID, version int
	if err := tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	fresh := applicationID == 0 && version == 0
	if fresh {
		var hasSchema bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM sqlite_schema)").Scan(&hasSchema); err != nil {
			return err
		}
		if hasSchema {
			return fmt.Errorf("refusing to initialize an existing unrecognized SQLite database")
		}
	} else if applicationID != storeApplicationID || version < 1 {
		return fmt.Errorf("not a Registration Gate database (application ID %d, schema version %d)", applicationID, version)
	}
	if version > len(storeMigrations) {
		return fmt.Errorf("Registration Gate database schema version %d is newer than supported version %d", version, len(storeMigrations))
	}

	for i := version; i < len(storeMigrations); i++ {
		if _, err := tx.ExecContext(ctx, storeMigrations[i]); err != nil {
			return fmt.Errorf("apply schema version %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			return err
		}
	}
	if fresh {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id = %d", storeApplicationID)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO store_scope VALUES (1, ?, ?)", scope.anchor, scope.namespace); err != nil {
			return err
		}
	} else {
		var stored storeScope
		if err := tx.QueryRowContext(ctx, "SELECT managed_anchor, namespace FROM store_scope WHERE singleton = 1").Scan(&stored.anchor, &stored.namespace); err != nil {
			return fmt.Errorf("read database scope: %w", err)
		}
		if stored != scope {
			return errStoreScope
		}
	}

	var integrity string
	if err := tx.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("SQLite quick check failed: %s", integrity)
	}
	var brokenReferences bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pragma_foreign_key_check)").Scan(&brokenReferences); err != nil {
		return err
	}
	if brokenReferences {
		return fmt.Errorf("SQLite foreign key check failed")
	}
	return tx.Commit()
}
