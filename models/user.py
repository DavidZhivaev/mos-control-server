from tortoise import fields, models

class User(models.Model):
    id = fields.IntField(pk=True)

    last_name = fields.CharField(max_length=100)
    first_name = fields.CharField(max_length=100)
    middle_name = fields.CharField(max_length=100, null=True)

    class_number = fields.IntField()
    class_letter = fields.CharField(max_length=1)
    building = fields.IntField()

    internet_overrides = fields.JSONField(default=dict)

    role = fields.IntField()
    password_hash = fields.CharField(max_length=255)

    is_activate = fields.BooleanField(default=True)

    storage_quota = fields.FloatField(default=0.25)