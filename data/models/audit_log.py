import datetime

class AuditLog:
    def __init__(self, user_id, event_category, event_action, event_status, timestamp=None, ip_address=None, mac_address=None, details=None):
        """
        Initializes an AuditLog instance.

        Args:
            user_id (str): The ID of the user associated with the event.
            event_category (str): The category of the event (e.g., "Authentication").
            event_action (str): The action performed (e.g., "User Login").
            event_status (str): The status of the event (e.g., "success" or "failed").
            timestamp (datetime.datetime, optional): The time the event occurred. Defaults to the current time if not provided.
            ip_address (str, optional): The IP address from which the event originated.
            mac_address (str, optional): The MAC address from which the event originated.
            details (str, optional): Additional details about the event.
        """
        self.user_id = user_id
        self.event_category = event_category
        self.event_action = event_action
        self.event_status = event_status
        self.timestamp = timestamp or datetime.datetime.now()  # Use provided timestamp or default to current time
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.details = details

    def __repr__(self):
        """
        Provides a string representation of the AuditLog instance.

        Returns:
            str: A string representation of the AuditLog instance including all its attributes.
        """
        return (
            f"AuditLog(user_id={self.user_id}, event_category={self.event_category}, "
            f"event_action={self.event_action}, event_status={self.event_status}, "
            f"timestamp={self.timestamp}, ip_address={self.ip_address}, "
            f"mac_address={self.mac_address}, details={self.details})"
        )
