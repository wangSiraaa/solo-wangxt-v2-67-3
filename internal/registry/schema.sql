-- Registry schema: packages, immutable versions, consumer declarations,
-- and persisted compatibility reports.

CREATE TABLE IF NOT EXISTS packages (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS versions (
    id             BIGSERIAL PRIMARY KEY,
    package_id     BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version        TEXT NOT NULL,
    content_hash   BYTEA NOT NULL,
    descriptor_set BYTEA NOT NULL,
    owned_paths    JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Immutability anchor: the service rejects same-version/different-content
    -- writes; it never updates this row.
    UNIQUE (package_id, version)
);

CREATE TABLE IF NOT EXISTS reports (
    id           BIGSERIAL PRIMARY KEY,
    package_id   BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    base_version TEXT NOT NULL,
    head_version TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    report       JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS reports_package_lookup
    ON reports (package_id, base_version, head_version);

CREATE TABLE IF NOT EXISTS consumers (
    id         BIGSERIAL PRIMARY KEY,
    package_id BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    consumer   TEXT NOT NULL,
    encoding   TEXT NOT NULL CHECK (encoding IN ('wire', 'json', 'both')),
    usages     JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (package_id, consumer)
);

-- Time-bound, consumer-scoped waivers for individual findings. Matching
-- at evaluation time is by finding fingerprint, so an exemption follows
-- the finding across later reports of the same package as long as the
-- semantic fingerprint is unchanged. EXPIRED is never stored: it is
-- derived from expires_at at read time.
CREATE TABLE IF NOT EXISTS exemptions (
    id           TEXT PRIMARY KEY,
    package_id   BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    finding      JSONB NOT NULL,           -- finding snapshot at request time
    base_version TEXT NOT NULL,            -- report the request was anchored to
    head_version TEXT NOT NULL,
    owner        TEXT NOT NULL,
    reason       TEXT NOT NULL,
    consumers    JSONB NOT NULL,           -- "*" covers all consumers
    requested_by TEXT NOT NULL,
    approved_by  TEXT NOT NULL DEFAULT '',
    revoked_by   TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REVOKED')),
    expires_at   TIMESTAMPTZ NOT NULL,
    request_id   TEXT,                     -- caller-supplied idempotency key
    version      BIGINT NOT NULL DEFAULT 1, -- optimistic concurrency token
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (request_id)                    -- NULLs never conflict
);

CREATE INDEX IF NOT EXISTS exemptions_package_lookup
    ON exemptions (package_id, fingerprint);

-- Audit trail: every state transition inserts one row in the same
-- transaction as the transition itself.
CREATE TABLE IF NOT EXISTS exemption_events (
    id           BIGSERIAL PRIMARY KEY,
    exemption_id TEXT NOT NULL REFERENCES exemptions(id) ON DELETE CASCADE,
    event        TEXT NOT NULL CHECK (event IN ('REQUESTED', 'APPROVED', 'REVOKED')),
    actor        TEXT NOT NULL,
    detail       JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS exemption_events_lookup
    ON exemption_events (exemption_id, id);
