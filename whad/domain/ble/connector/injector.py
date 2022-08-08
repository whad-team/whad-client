
from whad.domain.ble.connector import BLE
from whad.domain.ble import UnsupportedCapability, message_filter, BleDirection

class Injector(BLE):

    def __init__(self, device, connection=None):
        super().__init__(device)
        self.__connection = connection

        # Check if device accepts injection
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

    def inject_to_slave(self, packet):
        self.send_pdu(packet, access_address=self.__connection.access_address, direction=BleDirection.INJECTION_TO_SLAVE)
        message = self.wait_for_message(filter=message_filter('ble', 'injected'))
        return (message.ble.injected.success, message.ble.injected.injection_attempts)

    def inject_to_master(self, packet):
        self.send_pdu(packet, access_address=self.__connection.access_address, direction=BleDirection.INJECTION_TO_MASTER)
        message = self.wait_for_message(filter=message_filter('ble', 'injected'))
        return (message.ble.injected.success, message.ble.injected.injection_attempts)