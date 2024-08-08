from PyQt5 import QtWidgets, uic
from logic.aaa_analyzer import AAAAnalyzer, AAAEvent
from data.database import Database
import datetime

class AAAVerificationView(QtWidgets.QMainWindow):
    def __init__(self):
        super(AAAVerificationView, self).__init__()
        uic.loadUi('aaa_verification_view.ui', self)
        
        self.db = Database("connection_string_here")
        self.analyzer = AAAAnalyzer(self.db)
        
        self.verify_button.clicked.connect(self.verify_event)
    
    def verify_event(self):
        user_id = int(self.user_id_input.text())
        ip_address = self.ip_address_input.text()
        mac_address = self.mac_address_input.text()
        status = self.status_input.text()
        action = self.action_input.text()
        resource = self.resource_input.text()
        
        event = AAAEvent(
            user_id, 
            datetime.datetime.now(), 
            ip_address, 
            mac_address, 
            status, 
            action, 
            resource
        )
        countermeasures = self.analyzer.process_event(event)
        
        if countermeasures:
            self.result_text.setText(f"Countermeasures proposed: {', '.join(countermeasures)}")
        else:
            self.result_text.setText("Event verified and logged.")
