"""Permission modules, RbacRole, RolePermission + AccessGrant.rbac_role resource."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.orm import Session

revision: str = "027_rbac_governance_permissions"
down_revision: Union[str, None] = "026_migrate_appgroup_to_accessgrant"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    if table not in inspect(bind).get_table_names():
        return False
    return column in {c["name"] for c in inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "permission_modules" not in tables:
        op.create_table(
            "permission_modules",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("key", sa.String(), nullable=False),
            sa.Column("label", sa.String(), nullable=False),
            sa.Column("description", sa.String(), nullable=True),
            sa.Column("icon", sa.String(), nullable=True),
            sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
            sa.UniqueConstraint("key", name="uq_permission_modules_key"),
        )
        op.create_index("ix_permission_modules_key", "permission_modules", ["key"])

    if "rbac_roles" not in tables:
        op.create_table(
            "rbac_roles",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("inherits_from_id", sa.Integer(), nullable=True),
            sa.Column(
                "is_critical", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["inherits_from_id"], ["rbac_roles.id"]),
            sa.UniqueConstraint("name", name="uq_rbac_roles_name"),
        )
        op.create_index("ix_rbac_roles_name", "rbac_roles", ["name"])

    if "role_permissions" not in tables:
        op.create_table(
            "role_permissions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("role_id", sa.Integer(), nullable=False),
            sa.Column("module_id", sa.Integer(), nullable=False),
            sa.Column(
                "can_read", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column(
                "can_write", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column(
                "can_delete", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column(
                "can_execute", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column(
                "locked", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_by", sa.String(), nullable=True),
            sa.ForeignKeyConstraint(["role_id"], ["rbac_roles.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(
                ["module_id"], ["permission_modules.id"], ondelete="CASCADE"
            ),
            sa.UniqueConstraint("role_id", "module_id", name="uq_role_module"),
        )
        op.create_index("ix_role_permissions_role_id", "role_permissions", ["role_id"])
        op.create_index(
            "ix_role_permissions_module_id", "role_permissions", ["module_id"]
        )

    if "rbac_groups" in tables:
        if not _has_column(bind, "rbac_groups", "group_tag"):
            op.add_column(
                "rbac_groups", sa.Column("group_tag", sa.String(), nullable=True)
            )
        if not _has_column(bind, "rbac_groups", "description"):
            op.add_column(
                "rbac_groups", sa.Column("description", sa.String(), nullable=True)
            )

    if "access_grants" in tables and not _has_column(bind, "access_grants", "rbac_role_id"):
        with op.batch_alter_table("access_grants", recreate="always") as batch:
            batch.add_column(sa.Column("rbac_role_id", sa.Integer(), nullable=True))
            batch.create_foreign_key(
                "fk_access_grants_rbac_role_id",
                "rbac_roles",
                ["rbac_role_id"],
                ["id"],
            )
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

    session = Session(bind=bind)
    try:
        from app.rbac.permission_seed import seed_governance_rbac

        seed_governance_rbac(session)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())

    if "access_grants" in tables and _has_column(bind, "access_grants", "rbac_role_id"):
        with op.batch_alter_table("access_grants", recreate="always") as batch:
            batch.drop_constraint("ck_access_grant_resource_exclusive", type_="check")
            batch.create_check_constraint(
                "ck_access_grant_resource_exclusive",
                "(resource_type = 'application' AND application_id IS NOT NULL "
                "AND system_role IS NULL) OR "
                "(resource_type = 'system_role' AND system_role IS NOT NULL "
                "AND application_id IS NULL)",
            )
            batch.drop_constraint("fk_access_grants_rbac_role_id", type_="foreignkey")
            batch.drop_column("rbac_role_id")

    if "rbac_groups" in tables:
        if _has_column(bind, "rbac_groups", "description"):
            op.drop_column("rbac_groups", "description")
        if _has_column(bind, "rbac_groups", "group_tag"):
            op.drop_column("rbac_groups", "group_tag")

    if "role_permissions" in tables:
        op.drop_table("role_permissions")
    if "rbac_roles" in tables:
        op.drop_table("rbac_roles")
    if "permission_modules" in tables:
        op.drop_table("permission_modules")
