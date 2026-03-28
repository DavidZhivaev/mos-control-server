from tortoise import fields, models


class AuditLog(models.Model):
    id = fields.IntField(pk=True)

    created_at = fields.DatetimeField(auto_now_add=True)

    action = fields.CharField(max_length=64, index=True)

    actor = fields.ForeignKeyField(
        "models.User",
        related_name="audit_actions",
        null=True,
        on_delete=fields.SET_NULL,
    )
    actor_email_snapshot = fields.CharField(max_length=320, null=True)

    target_type = fields.CharField(max_length=64, null=True, index=True)
    target_id = fields.CharField(max_length=64, null=True, index=True)

    building = fields.IntField(null=True, index=True)

    ip = fields.CharField(max_length=45, null=True)
    user_agent = fields.TextField(null=True)

    success = fields.BooleanField(default=True)
    meta = fields.JSONField(default=dict)
