"""Initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-22
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("incident_id", sa.String(128), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("alert_name", sa.String(256), nullable=False),
        sa.Column("alert_timestamp", TZ, nullable=False),
        sa.Column("raw", sa.JSON, nullable=False),
        sa.Column("normalized", sa.JSON),
        sa.Column("cti_mode", sa.String(16), nullable=False),
        sa.Column("submitted_via", sa.String(32), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("worker_id", sa.String(64)),
        sa.Column("heartbeat_at", TZ),
        sa.Column("error", sa.Text),
        sa.Column("verdict", sa.String(32)),
        sa.Column("threat_score", sa.Integer),
        sa.Column("verdict_confidence", sa.Integer),
        sa.Column("human_review_required", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("report", sa.JSON),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("started_at", TZ),
        sa.Column("completed_at", TZ),
        sa.Column("duration_ms", sa.Integer),
    )
    op.create_index("ix_incidents_incident_id", "incidents", ["incident_id"], unique=True)
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_verdict", "incidents", ["verdict"])
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])

    op.create_table(
        "investigation_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("incident_pk", sa.Integer, sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("ts", TZ, nullable=False),
        sa.Column("type", sa.String(48), nullable=False),
        sa.Column("stage", sa.String(64)),
        sa.Column("status", sa.String(24)),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("data", sa.JSON),
        sa.UniqueConstraint("incident_pk", "seq", name="uq_event_seq"),
    )
    op.create_index("ix_investigation_events_incident_pk", "investigation_events", ["incident_pk"])

    op.create_table(
        "playbook_runs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("incident_pk", sa.Integer, sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("playbook", sa.String(128), nullable=False),
        sa.Column("playbook_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempt", sa.Integer, nullable=False),
        sa.Column("started_at", TZ, nullable=False),
        sa.Column("completed_at", TZ),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("error", sa.Text),
    )
    op.create_index("ix_playbook_runs_incident_pk", "playbook_runs", ["incident_pk"])

    op.create_table(
        "task_runs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("run_id", sa.Integer, sa.ForeignKey("playbook_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("node_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("order", sa.Integer, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("started_at", TZ),
        sa.Column("completed_at", TZ),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("logs", sa.JSON),
        sa.Column("output", sa.JSON),
        sa.Column("error", sa.Text),
    )
    op.create_index("ix_task_runs_run_id", "task_runs", ["run_id"])

    op.create_table(
        "cti_queries",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("incident_pk", sa.Integer, sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", sa.String(32)),
        sa.Column("provider", sa.String(48), nullable=False),
        sa.Column("indicator", sa.String(2048), nullable=False),
        sa.Column("indicator_type", sa.String(24), nullable=False),
        sa.Column("data_origin", sa.String(24), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("verdict", sa.String(24), nullable=False),
        sa.Column("threat_type", sa.String(128)),
        sa.Column("malware", sa.JSON),
        sa.Column("threat_actors", sa.JSON),
        sa.Column("confidence", sa.Integer),
        sa.Column("tags", sa.JSON),
        sa.Column("references", sa.JSON),
        sa.Column("mitre", sa.JSON),
        sa.Column("relationships", sa.JSON),
        sa.Column("first_seen", sa.String(64)),
        sa.Column("last_seen", sa.String(64)),
        sa.Column("freshness_days", sa.Float),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("http_status", sa.Integer),
        sa.Column("error", sa.Text),
        sa.Column("raw_response", sa.JSON),
        sa.Column("queried_at", TZ, nullable=False),
    )
    op.create_index("ix_cti_queries_incident_pk", "cti_queries", ["incident_pk"])
    op.create_index("ix_cti_queries_provider", "cti_queries", ["provider"])
    op.create_index("ix_cti_queries_indicator", "cti_queries", ["indicator"])

    op.create_table(
        "provider_credentials",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("encrypted_value", sa.Text, nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ts", TZ, nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("client_ip", sa.String(64)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(256)),
        sa.Column("details", sa.JSON),
    )
    op.create_index("ix_audit_logs_ts", "audit_logs", ["ts"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])


def downgrade() -> None:
    for t in ("audit_logs", "provider_credentials", "cti_queries", "task_runs", "playbook_runs",
              "investigation_events", "incidents"):
        op.drop_table(t)
