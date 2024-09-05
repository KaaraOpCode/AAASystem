class DictDatabase:
    def __init__(self):
        self.user_roles = {}
        self.user_permissions = {}
        self.known_ips = set()
        self.known_macs = set()
        self.resource_access = {}  # New attribute for resource access mapping
        self.logged_events = []
        self.failed_login_attempts = {}  # New attribute to store failed attempts

    def add_known_ip(self, ip):
        self.known_ips.add(ip)

    def add_known_mac(self, mac):
        self.known_macs.add(mac)

    def is_known_ip(self, ip):
        return ip in self.known_ips

    def is_known_mac(self, mac):
        # Corrected line
        return mac in self.known_macs

    def get_user_role(self, user_id):
        return self.user_roles.get(user_id, None)

    def get_permissions_for_action(self, action):
        permissions = []
        for user, actions in self.user_permissions.items():
            if action in actions:
                permissions.append(action)
        return permissions

    def has_role_permission(self, role, required_permissions):
        # Simulate permission check based on role
        role_permissions = self.resource_access.get(role, [])
        return all(perm in role_permissions for perm in required_permissions)

    def add_resource_access(self, role, permissions):
        self.resource_access[role] = permissions

    def log_event(self, event):
        self.logged_events.append(event)

    def get_failed_attempts(self, user_id):
        # Method to return the number of failed login attempts for a user
        return self.failed_login_attempts.get(user_id, 0)
    
    def increment_failed_attempts(self, user_id):
        # Method to increment failed login attempts
        self.failed_login_attempts[user_id] = self.get_failed_attempts(user_id) + 1

    def log_verified_event(self, event):
        self.logged_events.append(event)