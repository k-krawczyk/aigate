CREATE TABLE IF NOT EXISTS audit_event (
    id               VARCHAR(36)  PRIMARY KEY,
    ts               TIMESTAMP    NOT NULL,
    event_type       VARCHAR(32)  NOT NULL,
    client_id        VARCHAR(256),
    subject          VARCHAR(256),
    on_behalf_of     VARCHAR(256),
    auth_method      VARCHAR(160),
    model            VARCHAR(128),
    direction        VARCHAR(16),
    decision         VARCHAR(16),
    category         VARCHAR(64),
    owasp            VARCHAR(16),
    rules            VARCHAR(2048),
    excerpt          VARCHAR(1024),
    http_status      INT,
    prompt_tokens    BIGINT,
    completion_tokens BIGINT,
    cost_usd         DOUBLE PRECISION,
    latency_ms       DOUBLE PRECISION,
    step_micros      VARCHAR(2048),
    policy_revision  INT,
    detail           VARCHAR(4096),
    profile          VARCHAR(256),
    caller_groups    VARCHAR(4096)
);

-- Databases created before these columns existed (the Compose volume keeps the file across upgrades).
ALTER TABLE audit_event ADD COLUMN IF NOT EXISTS profile VARCHAR(256);
ALTER TABLE audit_event ADD COLUMN IF NOT EXISTS caller_groups VARCHAR(4096);
-- Widened after IdP integration: long provider names, Entra group GUIDs, merged profile names.
ALTER TABLE audit_event ALTER COLUMN client_id SET DATA TYPE VARCHAR(256);
ALTER TABLE audit_event ALTER COLUMN auth_method SET DATA TYPE VARCHAR(160);
ALTER TABLE audit_event ALTER COLUMN rules SET DATA TYPE VARCHAR(2048);
ALTER TABLE audit_event ALTER COLUMN profile SET DATA TYPE VARCHAR(256);
ALTER TABLE audit_event ALTER COLUMN caller_groups SET DATA TYPE VARCHAR(4096);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_event (ts);
CREATE INDEX IF NOT EXISTS idx_audit_client ON audit_event (client_id, ts);
