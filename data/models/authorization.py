from data.dict_database import DictDatabase


class Authorization:
    def __init__(self, database: DictDatabase):
        self.database = database

    def verify(self, user_id: str, action: str) -> bool:
        user_role = self.database.get_user_role(user_id)
        required_permissions = self.database.get_permissions_for_action(action)
        return self.database.has_role_permission(user_role, required_permissions)
