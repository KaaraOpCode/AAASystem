import datetime
from peewee import Model, CharField, DateTimeField, IntegerField, TextField
from playhouse.sqlite_ext import SqliteExtDatabase

# Initialize the database connection
db = SqliteExtDatabase('audit_log.db')

class BaseModel(Model):
    class Meta:
        database = db

class AuditLogModel(BaseModel):
    user_id = IntegerField()
    event_category = CharField()
    event_action = CharField()
    event_status = CharField()
    timestamp = DateTimeField(default=datetime.datetime.now)
    ip_address = CharField()
    mac_address = CharField()
    details = TextField()

    def save(self, *args, **kwargs):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now()
        super().save(*args, **kwargs)

# Create tables if they do not exist
db.connect()
db.create_tables([AuditLogModel], safe=True)
