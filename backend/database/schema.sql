CREATE TABLE projects (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_url TEXT NOT NULL,
    requested_revision TEXT NOT NULL DEFAULT 'HEAD',
    worker_count INTEGER NOT NULL CHECK (worker_count > 0 AND worker_count <= 2147483647),
    repository_token TEXT,
    commit_sha TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    paused_at TIMESTAMPTZ,
    error TEXT
);

CREATE TABLE tasks (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    error TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id)
);

CREATE TABLE assets (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    parent_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    validated_at TIMESTAMPTZ,
    error TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id),
    FOREIGN KEY (parent_id) REFERENCES assets (id)
);

CREATE TABLE campaigns (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL,
    target_asset_id BIGINT NOT NULL,
    configuration_asset_id BIGINT,
    engine TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    stopped_at TIMESTAMPTZ,
    last_heartbeat_at TIMESTAMPTZ,
    cpu_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    next_review_after TIMESTAMPTZ,
    next_review_reason TEXT,
    error TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id),
    FOREIGN KEY (target_asset_id) REFERENCES assets (id),
    FOREIGN KEY (configuration_asset_id) REFERENCES assets (id)
);

CREATE TABLE campaign_contexts (
    campaign_id BIGINT PRIMARY KEY,
    configuration_purpose TEXT NOT NULL,
    retirement_reason TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
);

CREATE TABLE campaign_progression_actions (
    action_id TEXT PRIMARY KEY,
    base_campaign_id BIGINT NOT NULL,
    campaign_id BIGINT NOT NULL UNIQUE,
    FOREIGN KEY (base_campaign_id) REFERENCES campaigns (id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
);

CREATE TABLE campaign_container_counters (
    campaign_id BIGINT NOT NULL,
    container_id TEXT NOT NULL,
    base_cpu_seconds DOUBLE PRECISION NOT NULL,
    last_raw_cpu_seconds DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (campaign_id, container_id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
);

CREATE TABLE campaign_artifacts (
    project_id BIGINT NOT NULL,
    campaign_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    accepted BOOLEAN NOT NULL,
    evidence_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    durable_relative_path TEXT,
    PRIMARY KEY (project_id, campaign_id, kind, content_sha256),
    FOREIGN KEY (project_id) REFERENCES projects (id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
);

CREATE TABLE campaign_artifact_cursors (
    project_id BIGINT NOT NULL,
    campaign_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    last_seen_ns BIGINT NOT NULL,
    last_name TEXT NOT NULL,
    PRIMARY KEY (project_id, campaign_id, kind),
    FOREIGN KEY (project_id) REFERENCES projects (id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
);

CREATE TABLE coverage_evidence (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL,
    commit_sha TEXT NOT NULL,
    source_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    function_name TEXT,
    campaign_id BIGINT NOT NULL,
    asset_id BIGINT NOT NULL,
    first_testcase_sha256 TEXT NOT NULL,
    cpu_exposure_seconds DOUBLE PRECISION NOT NULL,
    UNIQUE (project_id, commit_sha, source_path, line_number, asset_id),
    FOREIGN KEY (project_id) REFERENCES projects (id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
    FOREIGN KEY (asset_id) REFERENCES assets (id)
);

CREATE TABLE coverage_checkpoints (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL,
    campaign_id BIGINT NOT NULL,
    strategy_asset_id BIGINT NOT NULL,
    commit_sha TEXT NOT NULL,
    compatibility_group_id TEXT NOT NULL,
    observed_cpu_seconds DOUBLE PRECISION NOT NULL,
    reached_lines JSONB NOT NULL,
    reached_functions JSONB NOT NULL,
    recent_marginal_lines JSONB NOT NULL,
    crash_group_ids JSONB NOT NULL,
    crash_evidence_complete BOOLEAN NOT NULL,
    configuration_purpose TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
    FOREIGN KEY (strategy_asset_id) REFERENCES assets (id)
);

CREATE TABLE findings (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL,
    fingerprint TEXT NOT NULL,
    classification TEXT NOT NULL,
    priority_rank INTEGER,
    priority_reason TEXT,
    description TEXT NOT NULL,
    reproducible BOOLEAN NOT NULL,
    occurrence_count INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    triaged_at TIMESTAMPTZ,
    error TEXT,
    UNIQUE (project_id, fingerprint),
    FOREIGN KEY (project_id) REFERENCES projects (id)
);

CREATE TABLE campaign_crash_groups (
    campaign_id BIGINT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (campaign_id, fingerprint),
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
);

CREATE INDEX tasks_project_created_at_idx ON tasks (project_id, created_at, id);
CREATE INDEX assets_project_created_at_idx ON assets (project_id, created_at, id);
CREATE INDEX campaigns_project_started_at_idx ON campaigns (project_id, started_at, id);
CREATE INDEX coverage_evidence_project_source_line_idx ON coverage_evidence (project_id, source_path, line_number);
CREATE INDEX coverage_checkpoints_project_campaign_idx ON coverage_checkpoints (project_id, campaign_id, id);
CREATE INDEX findings_project_created_at_idx ON findings (project_id, created_at, id);

COMMENT ON SCHEMA public IS 'bigeye-schema:release-1';
