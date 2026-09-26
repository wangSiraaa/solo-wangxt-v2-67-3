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

-- Time-bounded exemptions for one deterministic finding. Reports
-- themselves are never rewritten: an exemption only changes the derived
-- publish decision computed at query time.
CREATE TABLE IF NOT EXISTS exemptions (
    id                BIGSERIAL PRIMARY KEY,
    package_id        BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    base_version      TEXT NOT NULL,
    head_version      TEXT NOT NULL,
    fingerprint       TEXT NOT NULL,
    original_severity TEXT NOT NULL,
    owner             TEXT NOT NULL,
    reason            TEXT NOT NULL,
    consumers         JSONB NOT NULL,
    requested_by      TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'REVOKED', 'EXPIRED')),
    approved_by       TEXT,
    rejected_by       TEXT,
    revoked_by        TEXT,
    expires_at        TIMESTAMPTZ,
    decided_at        TIMESTAMPTZ,
    -- Optimistic-concurrency token; every transition bumps it by one.
    version           BIGINT NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotent open requests: at most one still-open exemption per
-- (package, finding, requester). Terminal rows do not block a fresh
-- request, so a requester can re-apply after rejection/expiry.
CREATE UNIQUE INDEX IF NOT EXISTS exemptions_one_open_per_requester
    ON exemptions (package_id, fingerprint, requested_by)
    WHERE status IN ('PENDING', 'APPROVED');

CREATE INDEX IF NOT EXISTS exemptions_package_fingerprint
    ON exemptions (package_id, fingerprint);

-- Append-only audit trail. Every row is written in the same transaction
-- as the exemption transition it describes.
CREATE TABLE IF NOT EXISTS exemption_audit_events (
    id           BIGSERIAL PRIMARY KEY,
    exemption_id BIGINT NOT NULL REFERENCES exemptions(id) ON DELETE CASCADE,
    package_id   BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    action       TEXT NOT NULL CHECK (action IN ('REQUESTED', 'APPROVED', 'REJECTED', 'REVOKED', 'EXPIRED')),
    actor        TEXT NOT NULL,
    from_state   TEXT,
    to_state     TEXT NOT NULL,
    version      BIGINT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS exemption_audit_lookup
    ON exemption_audit_events (package_id, exemption_id, id);
