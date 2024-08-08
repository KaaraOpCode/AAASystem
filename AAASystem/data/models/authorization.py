class Authorization:
    def __init__(self, database):
        self.database = database

    def verify(self, user_id, action):
        role = self.database.get_user_role(user_id)
        if not role:
            return False

        permissions = self.database.get_user_permissions(user_id)
        return action in permissions
