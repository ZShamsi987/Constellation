CREATE TABLE IF NOT EXISTS workflow_schedule_firings (
    schedule_id TEXT NOT NULL REFERENCES workflow_schedules(id) ON DELETE CASCADE,
    due_at TEXT NOT NULL,
    run_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('claimed', 'started')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (schedule_id, due_at)
);

CREATE INDEX IF NOT EXISTS workflow_schedule_firings_status
ON workflow_schedule_firings(status, due_at);
