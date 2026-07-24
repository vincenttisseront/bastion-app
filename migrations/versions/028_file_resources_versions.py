"""FileResource, FileVersion, FileChannelAssignment + AccessGrant.file resource."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "028_file_resources_versions"
down_revision: Union[str, None] = "027_rbac_governance_permissions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    if table not in inspect(bind).get_table_names():
        return False
    return column in {c["name"] for c in inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "file_resources" not in tables:
        op.create_table(
            "file_resources",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("slug", sa.String(), nullable=False),
            sa.Column("label", sa.String(), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("category", sa.String(), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(), nullable=False),
            sa.UniqueConstraint("slug", name="uq_file_resources_slug"),
        )
        op.create_index("ix_file_resources_slug", "file_resources", ["slug"])
    else:
        # Mid-flight rename from early §7bis draft (enabled → is_active, + category).
        if _has_column(bind, "file_resources", "enabled") and not _has_column(
            bind, "file_resources", "is_active"
        ):
            with op.batch_alter_table("file_resources") as batch:
                batch.alter_column("enabled", new_column_name="is_active")
        if not _has_column(bind, "file_resources", "category"):
            op.add_column(
                "file_resources", sa.Column("category", sa.String(), nullable=True)
            )

    if "file_versions" not in tables:
        op.create_table(
            "file_versions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("file_id", sa.Integer(), nullable=False),
            sa.Column("channel", sa.String(), nullable=False),
            sa.Column("version_label", sa.String(), nullable=False),
            sa.Column("status", sa.String(), nullable=False, server_default="active"),
            sa.Column("original_filename", sa.String(), nullable=False),
            sa.Column("content_type", sa.String(), nullable=True),
            sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("checksum_sha256", sa.String(), nullable=False),
            sa.Column("storage_path", sa.String(), nullable=False),
            sa.Column("encrypted", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("uploaded_by", sa.String(), nullable=False),
            sa.Column("changelog", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(
                ["file_id"], ["file_resources.id"], ondelete="CASCADE"
            ),
            sa.UniqueConstraint("storage_path", name="uq_file_versions_storage_path"),
            sa.UniqueConstraint(
                "file_id", "version_label", name="uq_file_version_label"
            ),
            sa.CheckConstraint(
                "channel IN ('beta', 'stable')",
                name="ck_file_version_channel",
            ),
        )
        op.create_index("ix_file_versions_file_id", "file_versions", ["file_id"])
    else:
        with op.batch_alter_table("file_versions", recreate="always") as batch:
            if _has_column(bind, "file_versions", "storage_key"):
                batch.alter_column("storage_key", new_column_name="storage_path")
            if _has_column(bind, "file_versions", "notes"):
                batch.alter_column("notes", new_column_name="changelog")
            if not _has_column(bind, "file_versions", "encrypted"):
                batch.add_column(
                    sa.Column(
                        "encrypted",
                        sa.Boolean(),
                        nullable=False,
                        server_default=sa.false(),
                    )
                )
            batch.create_unique_constraint(
                "uq_file_version_label", ["file_id", "version_label"]
            )

    if "file_channel_assignments" not in tables:
        op.create_table(
            "file_channel_assignments",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("file_id", sa.Integer(), nullable=False),
            sa.Column("subject_type", sa.String(), nullable=False),
            sa.Column("rbac_group_id", sa.Integer(), nullable=True),
            sa.Column("keycloak_user_id", sa.String(), nullable=True),
            sa.Column("user_display_cache", sa.String(), nullable=True),
            sa.Column("channel", sa.String(), nullable=False, server_default="beta"),
            sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("assigned_by", sa.String(), nullable=False),
            sa.ForeignKeyConstraint(
                ["file_id"], ["file_resources.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(
                ["rbac_group_id"], ["rbac_groups.id"], ondelete="CASCADE"
            ),
            sa.UniqueConstraint(
                "file_id",
                "subject_type",
                "rbac_group_id",
                "keycloak_user_id",
                name="uq_file_channel_subject",
            ),
            sa.CheckConstraint(
                "channel = 'beta'",
                name="ck_file_channel_assignment_beta_only",
            ),
            sa.CheckConstraint(
                "(subject_type = 'group' AND rbac_group_id IS NOT NULL "
                "AND keycloak_user_id IS NULL) OR "
                "(subject_type = 'user' AND keycloak_user_id IS NOT NULL "
                "AND rbac_group_id IS NULL)",
                name="ck_file_channel_assignment_subject_exclusive",
            ),
        )
        op.create_index(
            "ix_file_channel_assignments_file_id",
            "file_channel_assignments",
            ["file_id"],
        )
        op.create_index(
            "ix_file_channel_assignments_keycloak_user_id",
            "file_channel_assignments",
            ["keycloak_user_id"],
        )
    elif not _has_column(bind, "file_channel_assignments", "file_id"):
        # Drop draft global assignments — per-file is the only supported model.
        op.drop_table("file_channel_assignments")
        op.create_table(
            "file_channel_assignments",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("file_id", sa.Integer(), nullable=False),
            sa.Column("subject_type", sa.String(), nullable=False),
            sa.Column("rbac_group_id", sa.Integer(), nullable=True),
            sa.Column("keycloak_user_id", sa.String(), nullable=True),
            sa.Column("user_display_cache", sa.String(), nullable=True),
            sa.Column("channel", sa.String(), nullable=False, server_default="beta"),
            sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("assigned_by", sa.String(), nullable=False),
            sa.ForeignKeyConstraint(
                ["file_id"], ["file_resources.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(
                ["rbac_group_id"], ["rbac_groups.id"], ondelete="CASCADE"
            ),
            sa.UniqueConstraint(
                "file_id",
                "subject_type",
                "rbac_group_id",
                "keycloak_user_id",
                name="uq_file_channel_subject",
            ),
            sa.CheckConstraint(
                "channel = 'beta'",
                name="ck_file_channel_assignment_beta_only",
            ),
            sa.CheckConstraint(
                "(subject_type = 'group' AND rbac_group_id IS NOT NULL "
                "AND keycloak_user_id IS NULL) OR "
                "(subject_type = 'user' AND keycloak_user_id IS NOT NULL "
                "AND rbac_group_id IS NULL)",
                name="ck_file_channel_assignment_subject_exclusive",
            ),
        )
        op.create_index(
            "ix_file_channel_assignments_file_id",
            "file_channel_assignments",
            ["file_id"],
        )
        op.create_index(
            "ix_file_channel_assignments_keycloak_user_id",
            "file_channel_assignments",
            ["keycloak_user_id"],
        )

    if "access_grants" in tables and not _has_column(bind, "access_grants", "file_id"):
        with op.batch_alter_table("access_grants", recreate="always") as batch:
            batch.add_column(sa.Column("file_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                "fk_access_grants_file_id",
                "file_resources",
                ["file_id"],
                ["id"],
            )
            batch.drop_constraint("ck_access_grant_resource_exclusive", type_="check")
            batch.create_check_constraint(
                "ck_access_grant_resource_exclusive",
                "(resource_type = 'application' AND application_id IS NOT NULL "
                "AND system_role IS NULL AND rbac_role_id IS NULL AND file_id IS NULL) OR "
                "(resource_type = 'system_role' AND system_role IS NOT NULL "
                "AND application_id IS NULL AND rbac_role_id IS NULL AND file_id IS NULL) OR "
                "(resource_type = 'rbac_role' AND rbac_role_id IS NOT NULL "
                "AND application_id IS NULL AND system_role IS NULL AND file_id IS NULL) OR "
                "(resource_type = 'file' AND file_id IS NOT NULL "
                "AND application_id IS NULL AND system_role IS NULL AND rbac_role_id IS NULL)",
            )
            batch.create_index("ix_access_grants_file_id", ["file_id"])


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "access_grants" in tables and _has_column(bind, "access_grants", "file_id"):
        with op.batch_alter_table("access_grants", recreate="always") as batch:
            batch.drop_constraint("ck_access_grant_resource_exclusive", type_="check")
            batch.create_check_constraint(
                "ck_access_grant_resource_exclusive",
                "(resource_type = 'application' AND application_id IS NOT NULL "
                "AND system_role IS NULL AND rbac_role_id IS NULL) OR "
                "(resource_type = 'system_role' AND system_role IS NOT NULL "
                "AND application_id IS NULL AND rbac_role_id IS NULL) OR "
                "(resource_type = 'rbac_role' AND rbac_role_id IS NOT NULL "
                "AND application_id IS NULL AND system_role IS NULL)",
            )
            batch.drop_constraint("fk_access_grants_file_id", type_="foreignkey")
            batch.drop_index("ix_access_grants_file_id")
            batch.drop_column("file_id")

    if "file_channel_assignments" in tables:
        op.drop_table("file_channel_assignments")
    if "file_versions" in tables:
        op.drop_table("file_versions")
    if "file_resources" in tables:
        op.drop_table("file_resources")
