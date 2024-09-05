from data.dict_database import DictDatabase

class AccessControl:
    def __init__(self, database: DictDatabase()):
        self.database = database

    def verify(self, user_id: str, resource: str) -> bool:
        user_role = self.database.get_user_role(user_id)
        return user_role in self.database.resource_access and resource in self.database.resource_access[user_role]
