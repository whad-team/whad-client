from whad.ble.connector import BLE
from whad.ble.exceptions import ConnectionLostException
from whad.ble import UnsupportedCapability, message_filter, BleDirection

class Injector(BLE):

    def __init__(self, device, connection):
        super().__init__(device)
        self.__connection = connection
        self.__exception = None
        # Check if device accepts injection
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

    def inject_to_slave(self, packet):
        if self.__connection is not None:
            self.send_pdu(packet, access_address=self.__connection.access_address, direction=BleDirection.INJECTION_TO_SLAVE)
            message = self.wait_for_message(filter=message_filter('ble', 'injected'))
            return (message.ble.injected.success, message.ble.injected.injection_attempts)
        else:
            raise self.__exception

    def inject_to_master(self, packet):
        if self.__connection is not None:
            self.send_pdu(packet, access_address=self.__connection.access_address, direction=BleDirection.INJECTION_TO_MASTER)
            message = self.wait_for_message(filter=message_filter('ble', 'injected'))
            return (message.ble.injected.success, message.ble.injected.injection_attempts)
        else:
            raise self.__exception

    def on_desynchronized(self, access_address):
        if access_address == self.__connection.access_address:
            self.__exception = ConnectionLostException(self.__connection)
            self.__connection = None
