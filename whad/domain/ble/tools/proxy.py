from time import sleep
from scapy.layers.bluetooth4LE import BTLE_DATA, BTLE_CTRL
from scapy.layers.bluetooth import L2CAP_Hdr
from whad.domain.ble.connector import BLE, Central, Peripheral, BleDirection
from whad.domain.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvCompleteLocalName
from whad.domain.ble.profile import GenericProfile
from whad.exceptions import WhadDeviceNotFound

def is_pdu_valid(pdu):
    if pdu.haslayer(BTLE_DATA):
        btle_data = pdu.getlayer(BTLE_DATA)
        if btle_data.LLID in [0x01, 0x02]:
            return btle_data.haslayer(L2CAP_Hdr)
        else:
            return (btle_data.LLID == 0x03)
    return False

def reshape_pdu(pdu):
    """This function remove any SN/NESN/MD bit as it is usually handled by
    the WHAD BLE-compatible dongle. Some BLE controllers and integrated stacks
    do not like to get PDUs with these bits set.

    :param Packet pdu: Bluetooth LE packet to process
    :return Packet: Clean Bluetooth LE packet
    """
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
                self.send_pdu(_pdu, self.__conn_handle)
        
        if len(self.__pending_data_pdus) > 0:
            for _pdu in self.__pending_data_pdus:
                self.send_pdu(_pdu, self.__conn_handle)

    def on_disconnected(self, connection_data):
        print('[!] client device disconnected')
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
        print('proxy >> central')
        pdu.show()
        print(pdu.metadata)
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            if self.__other_half is not None and self.__connected:
                print('send to central device')
                self.__other_half.forward_data_pdu(pdu)
            else:
                print('central not connected')

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
        print('[!] target device disconnected')
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
        print('central >> proxy')
        pdu.show()
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            if self.__other_half is not None and self.__connected:
                self.__other_half.forward_data_pdu(pdu)

    def forward_ctrl_pdu(self, pdu):
        if self.__conn_handle is not None:
            print('central is sending control pdu ...')
            return self.send_pdu(reshape_pdu(pdu), self.__conn_handle)
        else:
            print('central is not connected')

    def forward_data_pdu(self, pdu):
        if self.__conn_handle is not None:
            print('central is sending data pdu ...')
            return self.send_pdu(reshape_pdu(pdu), self.__conn_handle)
        else:
            print('central is not connected')

class LinkLayerProxy(object):
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

        # Callbacks
        self.__callbacks = []

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


class ImportedDevice(GenericProfile):
    def __init__(self, target, from_json):
        super().__init__(from_json=from_json)
        self.__target = target

    def on_characteristic_read(self, service, characteristic, offset=0, length=0):
        print('>> characteristic read')
        c = self.__target.get_characteristic(service.uuid, characteristic.uuid)
        return c.read(offset=offset)

    def on_characteristic_write(self, service, characteristic, offset=0, value=b'', without_response=False):
        """Characteristic write hook

        This hook is called whenever a charactertistic is about to be written by a GATT
        client. If this method returns None, then the write operation will return an error.
        """
        print('write %s to charac %s' % (value, characteristic.uuid))
        c = self.__target.get_characteristic(service.uuid, characteristic.uuid)
        c.write(value)
        print('written')
        return True

    def on_characteristic_subscribed(self, service, characteristic, notification=False, indication=False):
        """Not supported yet
        """
        pass

    def on_characteristic_unsubscribed(self, service, characteristic):
        """Not supported yet
        """
        pass

class GattProxy(object):
    """GATT Proxy
    """

    def __init__(self, proxy=None, target=None, adv_data=None, bd_address=None):
        self.__proxy_dev = proxy
        self.__target_dev = target
        if adv_data is None:
            self.__adv_data = AdvDataFieldList(
                AdvFlagsField(),
                AdvCompleteLocalName(b'BleProxy')
            )
        else:
            self.__adv_data = adv_data
        self.__target_bd_addr = bd_address

    def start(self):
        """Start our GATT Proxy
        """
        print('[i] Create central device ...')
        self.__central = Central(self.__target_dev)
        print('[i] Connect to target device ...')
        self.__target = self.__central.connect(self.__target_bd_addr)
        if self.__target is not None:
            print('[i] Connected, discover services and characteristics ...')
            self.__target.discover()
            print('[i] Services and characs discovered')
            target_profile = self.__target.export_json()
            
            # Once connected, we start our peripheral
            print('[i] Create our peripheral')
            self.__peripheral = Peripheral(self.__proxy_dev, profile=ImportedDevice(
                self.__target,
                target_profile
            ))
            self.__peripheral.enable_peripheral_mode(adv_data=self.__adv_data)

            # Start advertising
            print('[i] Start advertising')
            self.__peripheral.start()

