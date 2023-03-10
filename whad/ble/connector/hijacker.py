from whad.ble.connector import BLE, Central, Peripheral
from whad.ble import UnsupportedCapability, message_filter, BleDirection, Message, Connected

class Hijacker(BLE):

    def __init__(self, device, connection=None):
        super().__init__(device)
        self.__connection = connection
        self.__hijack_master = False
        self.__hijack_slave = False
        self.__status = False

        # Check if device accepts hijacking
        if not self.can_hijack_slave() and not self.can_hijack_master():
            raise UnsupportedCapability("Hijack")

    def available_actions(self, filter=None):
        actions = []
        if self.__status:
            # It should be replaced by arguments in function calls, building a pseudo packet seems dirty
            if self.__hijack_master:
                pseudo_connection = Message()
                pseudo_connection.ble.connected.CopyFrom(Connected())
                pseudo_connection.ble.connected.conn_handle = 0
                actions.append(Central(self.device, existing_connection=pseudo_connection.ble.connected))
            if self.__hijack_slave:
                pseudo_connection = Message()
                pseudo_connection.ble.connected.CopyFrom(Connected())
                pseudo_connection.ble.connected.conn_handle = 1
                actions.append(Peripheral(self.device, existing_connection=pseudo_connection.ble.connected))
        return [action for action in actions if filter is None or isinstance(action, filter)]

    def hijack(self, master = True, slave = False):
        """
        Hijack master, slave, or both
        """
        if master and slave:
            self.__hijack_master = master
            self.__hijack_slave = slave
            self.hijack_both(self.__connection.access_address)
        elif master:
            self.__hijack_master = master
            self.hijack_master(self.__connection.access_address)

        elif slave:
            self.__hijack_slave = slave
            self.hijack_slave(self.__connection.access_address)

        message = self.wait_for_message(filter=message_filter('ble', 'hijacked'))
        self.__status = message.ble.hijacked.success
        return (message.ble.hijacked.success)
