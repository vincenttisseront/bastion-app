"""FileFolder tree, folder-scoped FileResource, AccessGrant/Channel folder inheritance."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "030_file_folders_crushftp"
down_revision: Union[str, None] = "029_drop_resources_permission_module"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    if table not in inspect(bind).get_table_names():
        return False
    return column in {c["name"] for c in inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "file_folders" not in tables:
        op.create_table(
            "file_folders",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("parent_folder_id", sa.Integer(), nullable=True),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(), nullable=False),
            sa.ForeignKeyConstraint(
                ["parent_folder_id"], ["file_folders.id"], ondelete="CASCADE"
            ),
            sa.UniqueConstraint(
                "parent_folder_id", "name", name="uq_folder_name_per_parent"
            ),
        )
        op.create_index(
            "ix_file_folders_parent_folder_id", "file_folders", ["parent_folder_id"]
        )

    if "file_resources" in tables and not _has_column(bind, "file_resources", "folder_id"):
        with op.batch_alter_table("file_resources", recreate="always") as batch:
            batch.add_column(sa.Column("folder_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                "fk_file_resources_folder_id",
                "file_folders",
                ["folder_id"],
                ["id"],
                ondelete="SET NULL",
            )
            batch.create_index("ix_file_resources_folder_id", ["folder_id"])
            batch.create_unique_constraint(
                "uq_file_label_per_folder", ["folder_id", "label"]
            )

    if "access_grants" in tables and not _has_column(bind, "access_grants", "folder_id"):
        with op.batch_alter_table("access_grants", recreate="always") as batch:
            batch.add_column(sa.Column("folder_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                "fk_access_grants_folder_id",
                "file_folders",
                ["folder_id"],
                ["id"],
            )
            batch.drop_constraint("ck_access_grant_resource_exclusive", type_="check")
            batch.create_check_constraint(
                "ck_access_grant_resource_exclusive",
                "(resource_type = 'application' AND application_id IS NOT NULL "
                "AND system_role IS NULL AND rbac_role_id IS NULL "
                "AND file_id IS NULL AND folder_id IS NULL) OR "
                "(resource_type = 'system_role' AND system_role IS NOT NULL "
                "AND application_id IS NULL AND rbac_role_id IS NULL "
                "AND file_id IS NULL AND folder_id IS NULL) OR "
                "(resource_type = 'rbac_role' AND rbac_role_id IS NOT NULL "
                "AND application_id IS NULL AND system_role IS NULL "
                "AND file_id IS NULL AND folder_id IS NULL) OR "
                "(resource_type = 'file' AND file_id IS NOT NULL "
                "AND application_id IS NULL AND system_role IS NULL "
                "AND rbac_role_id IS NULL AND folder_id IS NULL) OR "
                "(resource_type = 'folder' AND folder_id IS NOT NULL "
                "AND application_id IS NULL AND system_role IS NULL "
                "AND rbac_role_id IS NULL AND file_id IS NULL)",
            )

    if "file_channel_assignments" in tables and not _has_column(
        bind, "file_channel_assignments", "folder_id"
    ):
        with op.batch_alter_table(
            "file_channel_assignments", recreate="always"
        ) as batch:
            batch.alter_column("file_id", existing_type=sa.Integer(), nullable=True)
            batch.add_column(sa.Column("folder_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                "fk_file_channel_assignments_folder_id",
                "file_folders",
                ["folder_id"],
                ["id"],
                ondelete="CASCADE",
            )
            batch.create_index("ix_file_channel_assignments_folder_id", ["folder_id"])
            try:
                batch.drop_constraint("uq_file_channel_subject", type_="unique")
            except Exception:
                pass
            batch.create_check_constraint(
                "ck_file_channel_target_exclusive",
                "(file_id IS NOT NULL AND folder_id IS NULL) OR "
                "(file_id IS NULL AND folder_id IS NOT NULL)",
            )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "file_channel_assignments" in tables and _has_column(
        bind, "file_channel_assignments", "folder_id"
    ):
        bind.execute(
            sa.text(
                "DELETE FROM file_channel_assignments WHERE file_id IS NULL"
            )
        )
        with op.batch_alter_table(
            "file_channel_assignments", recreate="always"
        ) as batch:
            batch.drop_constraint("ck_file_channel_target_exclusive", type_="check")
            batch.drop_column("folder_id")
            batch.alter_column("file_id", existing_type=sa.Integer(), nullable=False)

    if "access_grants" in tables and _has_column(bind, "access_grants", "folder_id"):
        bind.execute(
            sa.text("DELETE FROM access_grants WHERE resource_type = 'folder'")
        )
        with op.batch_alter_table("access_grants", recreate="always") as batch:
            batch.drop_constraint("ck_access_grant_resource_exclusive", type_="check")
            batch.drop_column("folder_id")
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

    if "file_resources" in tables and _has_column(bind, "file_resources", "folder_id"):
        with op.batch_alter_table("file_resources", recreate="always") as batch:
            try:
                batch.drop_constraint("uq_file_label_per_folder", type_="unique")
            except Exception:
                pass
            batch.drop_column("folder_id")

    if "file_folders" in tables:
        op.drop_table("file_folders")
