from time import sleep
from scapy.layers.bluetooth4LE import BTLE_DATA
from whad.domain.ble.connector import BLE, Central, Peripheral, BleDirection
from whad.domain.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvCompleteLocalName
from whad.exceptions import WhadDeviceNotFound

def reshape_pdu(pdu):
    btle_data = pdu.getlayer(BTLE_DATA)
    payload = btle_data.payload
    return BTLE_DATA(
        LLID=btle_data.LLID,
        len=len(payload)
    )/payload

class LowLevelPeripheral(Peripheral):
    """Link-layer only Peripheral implementation
    """
    def __init__(self, device, adv_data):
        super().__init__(device, adv_data=adv_data)
        self.__connected = False
        self.__conn_handle = None
        self.__other_half = None
        self.__pending_data_pdus = []
        self.__pending_control_pdus = []

    def set_other_half(self, other_half):
        self.__other_half = other_half

    def on_connected(self, connection_data):
        self.__connected = True
        if connection_data.conn_handle is None:
           self.__conn_handle = 0
        else: 
            self.__conn_handle = connection_data.conn_handle

        if len(self.__pending_control_pdus) > 0:
            for _pdu in self.__pending_control_pdus:
                self.send_ctrl_pdu(_pdu, self.__conn_handle)
        
        if len(self.__pending_data_pdus) > 0:
            for _pdu in self.__pending_data_pdus:
                self.send_data_pdu(_pdu, self.__conn_handle)

    def on_disconnected(self, connection_data):
        self.__connected = False
        self.__conn_handle = None

    def on_ctl_pdu(self, pdu):
        """This method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Peripheral devices act as a slave, so we only forward master to slave
        messages to the stack.
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            if self.__other_half is not None and self.__connected:
                self.__other_half.forward_ctrl_pdu(pdu)

    def on_data_pdu(self, pdu):
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            if self.__other_half is not None and self.__connected:
                self.__other_half.forward_data_pdu(pdu)

    def forward_ctrl_pdu(self, pdu):
        if self.__conn_handle is not None:
            return self.send_pdu(reshape_pdu(pdu), self.__conn_handle)
        else:
            self.__pending_control_pdus.append(reshape_pdu(pdu))

    def forward_data_pdu(self, pdu):
        if self.__conn_handle is not None:
            return self.send_pdu(reshape_pdu(pdu), self.__conn_handle)
        else:
            self.__pending_data_pdus.append(reshape_pdu(pdu))

class LowLevelCentral(Central):
    """Link-layer only Central implementation
    """

    def __init__(self, device):
        super().__init__(device)
        self.__connected = False
        self.__conn_handle = None
        self.__other_half = None

    def set_other_half(self, other_half):
        self.__other_half = other_half

    def is_connected(self):
        return self.__connected

    def peripheral(self):
        return True

    def on_connected(self, connection_data):
        """Override `on_connected` method to avoid notifying the stack. 

        We mark this low-level central as connected and save the connection
        handle.
        """
        self.__connected = True
        if connection_data.conn_handle is None:
           self.__conn_handle = 0
        else: 
            self.__conn_handle = connection_data.conn_handle

    def on_disconnected(self, connection_data):
        self.__connected = False
        self.__conn_handle = None

    def on_ctl_pdu(self, pdu):
        """Forward Control PDU to other half, if connected
        """
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            if self.__other_half is not None and self.__connected:
                self.__other_half.forward_ctrl_pdu(pdu)

    def on_data_pdu(self, pdu):
        """Forward Data PDU to other half, if connected
        """
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            if self.__other_half is not None and self.__connected:
                self.__other_half.forward_data_pdu(pdu)

    def forward_ctrl_pdu(self, pdu):
        if self.__conn_handle is not None:
            return self.send_pdu(reshape_pdu(pdu), self.__conn_handle)

    def forward_data_pdu(self, pdu):
        if self.__conn_handle is not None:
            return self.send_pdu(reshape_pdu(pdu), self.__conn_handle)

class GattProxy(object):
    """This class implements a GATT proxy that relies on two BLE-compatible
    WHAD devices to create a real BLE device that will proxify all the link-layer
    traffic to another device.
    """

    def __init__(self, proxy=None, target=None, adv_data=None, bd_address=None):
        """
        :param BLE proxy: BLE device to use as a peripheral (GATT Server)
        :param BLE target: BLE device to use as a central (GATT Client)
        :param AdvDataFieldList adv_data: Advertising data
        """
        if proxy is None or target is None or bd_address is None:
            raise WhadDeviceNotFound

        if adv_data is None:
            self.__adv_data = AdvDataFieldList(
                AdvFlagsField(),
                AdvCompleteLocalName(b'BleProxy')
            )
        else:
            self.__adv_data = adv_data

        # Save both devices
        self.__proxy = proxy
        self.__central = None
        self.__target = target
        self.__peripheral = None
        self.__target_bd_addr = bd_address

    def start(self):
        """Start proxy

        The proxy device will be set as a peripheral
        """
        
        # First, connect our central device to our target device
        print('[i] Create low-level central device ...')
        self.__central = LowLevelCentral(self.__target)
        print('[i] Connect to target device ...')
        if self.__central.connect(self.__target_bd_addr) is not None:
            print('[i] Connected, start our peripheral device ...')
            
            # Once connected, we start our peripheral
            print('[i] Create low-level peripheral')
            self.__peripheral = LowLevelPeripheral(
                self.__proxy,
                self.__adv_data
            )
            # Interconnect central and peripheral
            print('[i] Interconnect central and peripheral ...')
            self.__peripheral.set_other_half(self.__central)
            self.__central.set_other_half(self.__peripheral)
            
            # Start advertising
            print('[i] Start advertising')
            self.__peripheral.start()






