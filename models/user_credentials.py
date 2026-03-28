from tortoise import fields, models


class UserCredentials(models.Model):
    id = fields.IntField(pk=True)
    
    user = fields.OneToOneField(
        "models.User",
        related_name="credentials",
        on_delete=fields.CASCADE,
    )
    
    password_hash = fields.CharField(max_length=255)
    
    password_changed_at = fields.DatetimeField(null=True)
    
    password_history = fields.JSONField(default=list)
    
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    
    class Meta:
        table = "user_credentials"
    
    def __str__(self):
        return f"Credentials for user {self.user_id}"
