import datetime

class AAAEvent:
    def __init__(self, user_id, timestamp=None, ip_address=None, mac_address=None, status=None, action=None, resource=None):
        """
        Initializes an AAAEvent instance.

        Args:
            user_id (str): The ID of the user associated with the event.
            timestamp (datetime.datetime, optional): The time the event occurred. Defaults to the current time if not provided.
            ip_address (str, optional): The IP address from which the event originated.
            mac_address (str, optional): The MAC address from which the event originated.
            status (str, optional): The status of the event (e.g., "success" or "failed").
            action (str, optional): The action performed during the event (e.g., "login").
            resource (str, optional): The resource involved in the event (e.g., "dashboard").
        """
        self.user_id = user_id
        self.timestamp = timestamp or datetime.datetime.now()  # Use provided timestamp or default to current time
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.status = status
        self.action = action
        self.resource = resource

    def __str__(self):
        """
        Provides a human-readable string representation of the AAAEvent instance.

        Returns:
            str: A formatted string including user ID, timestamp, IP address, MAC address, status, action, and resource.
        """
        return (
            f"User ID: {self.user_id}, Timestamp: {self.timestamp}, IP Address: {self.ip_address}, "
            f"MAC Address: {self.mac_address}, Status: {self.status}, Action: {self.action}, "
            f"Resource: {self.resource}"
        )

    def __repr__(self):
        """
        Provides a detailed string representation of the AAAEvent instance, suitable for debugging.

        Returns:
            str: A detailed string representation of the AAAEvent instance including all its attributes.
        """
        return (
            f"AAAEvent(user_id={self.user_id!r}, timestamp={self.timestamp!r}, "
            f"ip_address={self.ip_address!r}, mac_address={self.mac_address!r}, "
            f"status={self.status!r}, action={self.action!r}, resource={self.resource!r})"
        )
