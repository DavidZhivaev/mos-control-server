from tortoise import fields, models


class User(models.Model):
    id = fields.IntField(pk=True)

    login = fields.CharField(max_length=32, unique=True, index=True)

    contact_method = fields.CharField(max_length=500, null=True)

    last_name = fields.CharField(max_length=100)
    first_name = fields.CharField(max_length=100)
    middle_name = fields.CharField(max_length=100, null=True)

    class_number = fields.IntField(null=True)
    class_letter = fields.CharField(max_length=1, null=True)
    building = fields.IntField()

    internet_overrides = fields.JSONField(default=dict)

    role = fields.IntField()
    password_hash = fields.CharField(max_length=255)

    is_active = fields.BooleanField(default=True)

    is_banned = fields.BooleanField(default=False)
    ban_reason = fields.TextField(null=True)
    banned_at = fields.DatetimeField(null=True)
    banned_by = fields.ForeignKeyField(
        "models.User",
        related_name="bans_issued",
        null=True,
        on_delete=fields.SET_NULL,
    )

    can_access_personal_data = fields.BooleanField(default=False)

    storage_quota = fields.FloatField(default=0.25)

    last_edited_by = fields.ForeignKeyField(
        "models.User",
        related_name="users_last_edited",
        null=True,
        on_delete=fields.SET_NULL,
    )
    last_edited_at = fields.DatetimeField(null=True)

    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
