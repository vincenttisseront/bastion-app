"""Remove dead PermissionModule seed key « resources » (mock /admin/resources page).

No dedicated resource-provisioning table ever existed; only the governance seed
row and RolePermission links for key=resources are cleaned up.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision: str = "029_drop_resources_permission_module"
down_revision: Union[str, None] = "028_file_resources_versions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "permission_modules" not in tables:
        return

    module_id = bind.execute(
        sa.text("SELECT id FROM permission_modules WHERE key = :key"),
        {"key": "resources"},
    ).scalar()
    if module_id is None:
        return

    if "role_permissions" in tables:
        bind.execute(
            sa.text("DELETE FROM role_permissions WHERE module_id = :mid"),
            {"mid": module_id},
        )
    bind.execute(
        sa.text("DELETE FROM permission_modules WHERE id = :mid"),
        {"mid": module_id},
    )


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if "permission_modules" not in tables:
        return
    existing = bind.execute(
        sa.text("SELECT id FROM permission_modules WHERE key = :key"),
        {"key": "resources"},
    ).scalar()
    if existing is not None:
        return
    bind.execute(
        sa.text(
            "INSERT INTO permission_modules (key, label, description, icon, sort_order) "
            "VALUES (:key, :label, :description, :icon, :sort_order)"
        ),
        {
            "key": "resources",
            "label": "Ressources",
            "description": "Ressources administrateur",
            "icon": "inventory_2",
            "sort_order": 80,
        },
    )
