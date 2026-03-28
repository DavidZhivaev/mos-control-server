from tortoise import fields, models


class Notification(models.Model):
    id = fields.IntField(pk=True)

    user = fields.ForeignKeyField("models.User", related_name="notifications", on_delete=fields.CASCADE)
    
    title = fields.CharField(max_length=200)
    message = fields.TextField()
    
    is_read = fields.BooleanField(default=False)
    is_system = fields.BooleanField(default=False)
    
    created_by = fields.ForeignKeyField(
        "models.User",
        related_name="created_notifications",
        null=True,
        on_delete=fields.SET_NULL,
    )
    
    created_at = fields.DatetimeField(auto_now_add=True)
    read_at = fields.DatetimeField(null=True)
