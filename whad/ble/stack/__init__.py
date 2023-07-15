"""
Pythonic Bluetooth LE stack
"""
from whad.ble.stack.gatt import GattClient
from whad.common.stack import Stack
from .llm import BleLinkLayerManager, NewLinkLayer
from .l2cap import NewL2CAPLayer
from .constants import BtVersion

class NewBleStack(Stack):
    """New BLE Stack using WHAD Stack model
    """

    def __init__(self, connector, bt_version=BtVersion(4, 0), manufacturer=0x0002, sub_version=0x0100, options={}):
        super().__init__(options=options)

        # Save connector (used as PHY layer)
        self.__connector = connector

        # Store BT supported version, manufacturer and sub version
        self.__version = bt_version
        self.__manufacturer = manufacturer
        self.__sub_version = sub_version

    @property
    def bt_version(self):
        return self.__version
    
    @property
    def manufacturer_id(self):
        return self.__manufacturer
    
    @property
    def bt_sub_version(self):
        return self.__sub_version

    def on_connection(self, conn_handle, local_peer_addr, remote_peer_addr):
        connection = self.get_layer('ll').on_connect(
            conn_handle,
            local_peer_addr,
            remote_peer_addr
        )
        self.__connector.on_new_connection(connection)

    def on_disconnection(self, conn_handle, reason):
        self.get_layer('ll').on_disconnect(conn_handle)

    def on_ctl_pdu(self, conn_handle, control):
        self.feed(control, tag='control', conn_handle=conn_handle)

    def on_data_pdu(self, conn_handle, data):
        self.feed(data, tag='data', conn_handle=conn_handle)

    def send_data(self, conn_handle, data, encrypt=None):
        return self.__connector.send_data_pdu(data, conn_handle=conn_handle, encrypt=encrypt)

    def send_control(self, conn_handle, pdu, encrypt=None):
        self.__connector.send_ctrl_pdu(pdu, conn_handle, encrypt=encrypt)

NewBleStack.layer(NewL2CAPLayer)
NewBleStack.layer(NewLinkLayer)

class BleStack:
    """
    This class holds the main components of a (hackable) BLE stack:

    - the Link Layer Manager (LLM)
    - the L2CAP manager
    - the Generic Access Profile controller (GAP)
    - the Generic Attribute Profile controller (GATT)
    - the Attribute Protocol (ATT)
    - the Security Manager (SMP)

    The Link-layer manager handles all the low-level operations:
    - BLE connection control (handles Control PDUs)
    - BLE connection data (forward to upper layer, i.e. L2CAP)
    """

    def __init__(self, connector, gatt_class=None, bt_version=BtVersion(4, 0), manufacturer=0x0002, sub_version=0x0100):
        """
        Create an instance of BleStack associated with a specific connector. This
        connector provides the transport layer.

        :param WhadDeviceConnector connector: Connector to use with this stack.
        """
        self.__connector = connector

        # Store BT supported version, manufacturer and sub version
        self.__version = bt_version
        self.__manufacturer = manufacturer
        self.__sub_version = sub_version

        # Instanciate all the required controllers
        self.__llm = BleLinkLayerManager(self, gatt_class)

    @property
    def manufacturer_id(self):
        return self.__manufacturer

    @property
    def bt_version(self):
        return self.__version.value

    @property
    def bt_sub_version(self):
        return self.__sub_version


    #############################
    # Incoming messages
    #############################

    def on_connection(self, conn_handle, local_peer_addr, remote_peer_addr):
        connection = self.__llm.on_connect(
            conn_handle,
            local_peer_addr,
            remote_peer_addr
        )
        self.__connector.on_new_connection(connection)

    def on_disconnection(self, conn_handle, reason):
        self.__llm.on_disconnect(conn_handle)

    def on_ctl_pdu(self, conn_handle, control):
        self.__llm.on_ctl_pdu(conn_handle, control)

    def on_data_pdu(self, conn_handle, data):
        self.__llm.on_data_pdu(conn_handle, data)

    def send_data(self, conn_handle, data, encrypt=None):
        return self.__connector.send_data_pdu(data, conn_handle=conn_handle, encrypt=encrypt)

    def send_control(self, conn_handle, pdu, encrypt=None):
        self.__connector.send_ctrl_pdu(pdu, conn_handle, encrypt=encrypt)

    def set_encryption(self, conn_handle, enabled, key, iv):
        """Notify encryption status directly

        Call connector's `notify_encryption_status()` method usually implemented
        in BLE in order to notify the underlying WHAD device that encryption has
        been enabled or not.
        """
        return self.__connector.set_encryption(enabled=enabled, key=key, iv=iv)

    ############################
    # Interact
    ############################
