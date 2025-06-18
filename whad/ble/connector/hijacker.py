"""Bluetooth Low Energy connection hijacker connector.
"""
from whad.ble.connector.base import BLE
from whad.ble.connector.central import Central
from whad.ble.connector.peripheral import Peripheral
from whad.ble.exceptions import ConnectionLostException
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter
from whad.hub.events import ConnectionEvt
from whad.hub.ble import Hijacked

class Hijacker(BLE):
    """Bluetooth Low Energy hijacking connector.
    """

    def __init__(self, device, connection=None):
        super().__init__(device)
        self.__connection = connection
        self.__hijack_master = False
        self.__hijack_slave = False
        self.__status = False
        self.__exception = None
        # Check if device accepts hijacking
        if not self.can_hijack_slave() and not self.can_hijack_master():
            raise UnsupportedCapability("Hijack")

    @property
    def central(self) -> Central:
        """Return the hijacker central.
        """
        available_actions = self.available_actions(Central)
        if len(available_actions) == 1:
            return available_actions[0]
        return None

    @property
    def peripheral(self):
        """Return the hijacker peripheral.
        """
        available_actions = self.available_actions(Peripheral)
        if len(available_actions) == 1:
            return available_actions[0]
        return None

    def available_actions(self, action_filter=None):
        """Determine the possible actions once a connection has been hijacked.
        """
        actions = []
        if self.__status:
            # It should be replaced by arguments in function calls, building a\
            # pseudo packet seems dirty
            if self.__hijack_master:
                pseudo_connection = ConnectionEvt()
                pseudo_connection.conn_handle = 0
                pseudo_connection.initiator = b"\x00\x00\x00\x00\x00\x00"
                pseudo_connection.init_addr_type = 0
                pseudo_connection.advertiser = b"\x00\x00\x00\x00\x00\x00"
                pseudo_connection.adv_addr_type = 0
                actions.append(Central(self.device, existing_connection=pseudo_connection))
            if self.__hijack_slave:
                pseudo_connection = ConnectionEvt()
                pseudo_connection.conn_handle = 1
                pseudo_connection.initiator = b"\x00\x00\x00\x00\x00\x00"
                pseudo_connection.init_addr_type = 0
                pseudo_connection.advertiser = b"\x00\x00\x00\x00\x00\x00"
                pseudo_connection.adv_addr_type = 0

                actions.append(
                    Peripheral(
                        self.device,
                        existing_connection = pseudo_connection
                    )
                )
        return [action for action in actions if action_filter is None or isinstance(action, filter)]


    def hijack(self, master = True, slave = False):
        """
        Hijack master, slave, or both
        """
        if self.__connection is not None:
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

            message = self.wait_for_message(keep=message_filter(Hijacked))
            self.__status = message.success
            return message.success

        # Connection failed
        raise self.__exception

    def on_desynchronized(self, access_address=None):
        """Desynchronization callback
        """
        if access_address == self.__connection.access_address:
            self.__exception = ConnectionLostException(self.__connection)
            self.__connection = None
