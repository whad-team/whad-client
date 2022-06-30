"""
Pythonic Bluetooth LE stack
"""
from .llm import BleLinkLayerManager

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
    
    def __init__(self, connector):
        """
        Create an instance of BleStack associated with a specific connector. This
        connector provides the transport layer.

        :param WhadDeviceConnector connector: Connector to use with this stack.
        """
        self.__connector = connector

        # Instanciate all the required controllers
        self.__llm = BleLinkLayerManager(self)

    #############################
    # Incoming messages
    #############################

    def on_connection(self, connection_data):
        connection = self.__llm.on_connect(connection_data)
        self.__connector.on_new_connection(connection)

    def on_disconnection(self, conn_handle):
        self.__llm.on_disconnect(conn_handle)
        self.__connector.on_disconnect(conn_handle)

    def on_ctl_pdu(self, conn_handle, control):
        self.__llm.on_ctl_pdu(conn_handle, control)

    def on_data_pdu(self, conn_handle, data):
        print('received data pdu for conhandle %d', conn_handle)
        self.__llm.on_data_pdu(conn_handle, data)

    def send_data(self, conn_handle, data):
        self.__connector.send_data_pdu(conn_handle, data)

    ############################
    # Interact
    ############################
