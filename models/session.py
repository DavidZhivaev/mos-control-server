from tortoise import fields, models


class Session(models.Model):
    id = fields.UUIDField(pk=True)

    user = fields.ForeignKeyField("models.User", related_name="sessions")

    ip = fields.CharField(max_length=45)
    user_agent = fields.TextField()

    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()

    max_expires_at = fields.DatetimeField()

    is_active = fields.BooleanField(default=True)
    refresh_version = fields.IntField(default=0)
