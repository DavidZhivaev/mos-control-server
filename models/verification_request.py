from tortoise import fields, models


class VerificationRequest(models.Model):
    id = fields.IntField(pk=True)

    status = fields.CharField(max_length=20, default="pending", index=True)

    last_name = fields.CharField(max_length=100)
    first_name = fields.CharField(max_length=100)
    class_number = fields.IntField()
    class_letter = fields.CharField(max_length=1)

    building = fields.IntField()

    login = fields.CharField(max_length=32, index=True)
    password_hash = fields.CharField(max_length=255)

    contact_method = fields.CharField(max_length=500, null=True)

    submitter_ip = fields.CharField(max_length=45, null=True)

    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    processed_at = fields.DatetimeField(null=True)
    reject_reason = fields.TextField(null=True)

    processed_by = fields.ForeignKeyField(
        "models.User",
        related_name="verification_requests_processed",
        null=True,
        on_delete=fields.SET_NULL,
    )
    created_user = fields.ForeignKeyField(
        "models.User",
        related_name="verification_request_source",
        null=True,
        on_delete=fields.SET_NULL,
    )
