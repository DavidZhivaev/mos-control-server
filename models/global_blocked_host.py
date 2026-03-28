from tortoise import fields, models


class GlobalBlockedHost(models.Model):
    id = fields.IntField(pk=True)
    hostname = fields.CharField(max_length=253, unique=True, index=True)
    note = fields.CharField(max_length=500, null=True)
    is_active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    created_by = fields.ForeignKeyField(
        "models.User",
        related_name="global_blocks_created",
        null=True,
        on_delete=fields.SET_NULL,
    )


class UserHostOverride(models.Model):
    id = fields.IntField(pk=True)
    user = fields.ForeignKeyField(
        "models.User", related_name="host_overrides", on_delete=fields.CASCADE
    )
    hostname = fields.CharField(max_length=253, index=True)
    effect = fields.CharField(max_length=10)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    created_by = fields.ForeignKeyField(
        "models.User",
        related_name="host_overrides_created",
        null=True,
        on_delete=fields.SET_NULL,
    )
