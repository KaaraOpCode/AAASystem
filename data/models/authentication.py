# data/models/authentication.py
print("authentication.py loaded")

class Authentication:
    print("Authentication class defined")

    def __init__(self, database):
        """
        Initializes an Authentication instance.

        Args:
            database (DictDatabase): An instance of DictDatabase to interact with the database.
        """
        self.database = database

    def verify(self, user_id, status, ip_address, mac_address):
        """
        Verifies the authentication details of a user.

        Args:
            user_id (str): The ID of the user trying to authenticate.
            status (str): The authentication status, e.g., 'success' or 'failed'.
            ip_address (str): The IP address from which the authentication attempt was made.
            mac_address (str): The MAC address associated with the authentication attempt.

        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        print(f"Verifying authentication for user: {user_id}")
        print(f"Status: {status}, IP Address: {ip_address}, MAC Address: {mac_address}")
        
        # Retrieve data related to the user's previous authentication attempts
        failed_attempts = self.database.get_failed_attempts(user_id)
        known_ip = self.database.is_known_ip(ip_address)
        known_mac = self.database.is_known_mac(mac_address)
        
        # Check if the account is locked due to too many failed attempts
        if failed_attempts > 3:
            print("Account locked due to too many failed attempts.")
            return False
        
        # Check if the IP address and MAC address are recognized
        if not known_ip:
            print("IP address not recognized.")
        
        if not known_mac:
            print("MAC address not recognized.")
        
        # Simulate successful verification if all conditions are met
        if known_ip and known_mac and failed_attempts <= 3:
            print("Authentication successful.")
            return True
        
        # Authentication failed if any condition is not met
        print("Authentication failed.")
        return False
