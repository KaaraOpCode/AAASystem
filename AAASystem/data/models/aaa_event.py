import datetime

class AAAEvent:
    def __init__(self, user_id, timestamp, ip_address, mac_address, status, action=None, resource=None):
        self.user_id = user_id
        self.timestamp = timestamp
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.status = status
        self.action = action  # Action for authorization events
        self.resource = resource  # Resource for access events

    def __str__(self):
        return (
            f"User ID: {self.user_id}, Timestamp: {self.timestamp}, IP Address: {self.ip_address}, "
            f"MAC Address: {self.mac_address}, Status: {self.status}, Action: {self.action}, "
            f"Resource: {self.resource}"
        )
