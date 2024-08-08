# data/models/database.py
class DictDatabase:
    def __init__(self):
        self.failed_attempts = {}
        self.known_ips = set()
        self.known_macs = set()
        self.logged_events = []
        # Mock user roles
        self.user_roles = {
            'admin_user': 'admin',
            'teacher_user': 'teacher',
            'student_user': 'student',
            'unknown_user': None
        }

    def add_known_ip(self, ip):
        self.known_ips.add(ip)

    def add_known_mac(self, mac):
        self.known_macs.add(mac)

    def add_failed_attempt(self, user_id):
        if user_id in self.failed_attempts:
            self.failed_attempts[user_id] += 1
        else:
            self.failed_attempts[user_id] = 1

    def get_failed_attempts(self, user_id):
        return self.failed_attempts.get(user_id, 0)

    def is_known_ip(self, ip):
        return ip in self.known_ips

    def is_known_mac(self, mac):
        return mac in self.known_macs

    def log_verified_event(self, event):
        print(f"Logging event: {event}")
        self.logged_events.append(event)

    def get_user_role(self, user_id):
        return self.user_roles.get(user_id, None)
