"""This module provides specific classes to set-up a BLE proxy.

The class :class:`LinkLayerProxy` provides a link-layer level BLE proxy that
will connect to a target device, spawns another device and relay control and
data PDUs between a client and the target device.

The class :class:`GattProxy` provides a GATT BLE proxy that will connect to a
target device, creates another device and relay GATT operations (characteristic
read, write, notification and indication) between a client and the target
device.
"""
import logging

from scapy.layers.bluetooth4LE import BTLE_DATA
from scapy.layers.bluetooth import L2CAP_Hdr

from whad.hub.ble import BDAddress
from whad.ble.connector import Central, Peripheral
from whad.ble.connector.central import CentralDisconnected
from whad.ble.connector.peripheral import PeripheralEventListener, PeripheralEventConnected, \
    PeripheralEventDisconnected
from whad.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvCompleteLocalName
from whad.ble.profile import GenericProfile
from whad.ble.exceptions import HookReturnValue, HookDontForward, ConnectionLostException
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.exceptions import WhadDeviceNotFound
from whad.common.monitors import PcapWriterMonitor, WiresharkMonitor
from whad.hub.ble import Direction as BleDirection


logger = logging.getLogger(__name__)

#############################################
# Link-layer Proxy related classes
#############################################

def is_pdu_valid(pdu):
    """Check if a given PDU is valid (either Data or Control PDU)

    :param Packet pdu: PDU to check
    :rtype: bool
    :return: True if PDU is valid, False otherwise
    """
    if pdu.haslayer(BTLE_DATA):
        btle_data = pdu.getlayer(BTLE_DATA)
        if btle_data.LLID in [0x01, 0x02]:
            return btle_data.haslayer(L2CAP_Hdr)

        # Control PDU
        return btle_data.LLID == 0x03
    return False


def reshape_pdu(pdu):
    """This function remove any SN/NESN/MD bit as it is usually handled by
    the WHAD BLE-compatible dongle. Some BLE controllers and integrated stacks
    do not like to get PDUs with these bits set.

    :param Packet pdu: Bluetooth LE packet to process
    :return Packet: Clean Bluetooth LE packet
    """
    # Reset SN/NESN/MD bits
    btle_data = pdu.getlayer(BTLE_DATA)
    payload = btle_data.payload
    return BTLE_DATA(
        LLID=btle_data.LLID,
        len=len(payload)
    )/payload


class LowLevelPeripheral(Peripheral):
    """Link-layer only Peripheral implementation

    This class is used by the :class:`whad.ble.tools.proxy.LinkLayerProxy` class
    to provide a Link-Layer peripheral with the requested advertising data.
    """

    def __init__(self, proxy, device, adv_data, scan_data, bd_address=None, public=True):
        """Instantiate a LowLevelPeripheral instance

        :param LinkLayerProxy proxy: Reference to the link-layer proxy that will receive events
        :param WhadDevice device: A :class:`whad.device.WhadDevice` object to use
                                  as the physical link
        :param AdvDataFieldList adv_data: Advertising data of the exposed proxy device (mandatory)
        :param AdvDataFieldList scan_data: Scan response data of the exposed proxy
                                           device (optional, can be None)
        """
        super().__init__(device, adv_data=adv_data, scan_data=scan_data, bd_address=bd_address, public=public)
        self.__proxy = proxy
        self.__connected = False
        self.__conn_handle = None
        self.__other_half = None
        self.__pending_data_pdus = []
        self.__pending_control_pdus = []

    @property
    def conn_handle(self):
        return self.__conn_handle

    def set_other_half(self, other_half):
        """Set the *other half*, i.e. the reference to a :class:`LowLevelCentral`
        device connected to the target device

        :param LowLevelCentral other_half: Link-layer Central device to notify events
        """
        self.__other_half = other_half

    def on_connected(self, connection_data):
        """Callback to handle link-layer connection from the underlying peripheral connector

        :param connection_data: Connection data object
        """
        self.__connected = True
        if connection_data.conn_handle is None:
            self.__conn_handle = 0
        else:
            self.__conn_handle = connection_data.conn_handle

        local_peer = BDAddress.from_bytes(
            connection_data.advertiser,
            connection_data.adv_addr_type
        )
        remote_peer = BDAddress.from_bytes(
            connection_data.initiator,
            connection_data.init_addr_type
        )

        # Notify event listener
        self.notify_event(PeripheralEventConnected(
            connection_data.conn_handle,
            local_peer,
            remote_peer
        ))

        # Notify proxy that a connection has been established
        if self.__proxy is not None:
            self.__proxy.on_connect()

        # Foward pending PDUs
        if len(self.__pending_control_pdus) > 0:
            for _pdu in self.__pending_control_pdus:
                if self.__proxy is not None:
                    pdu = self.__proxy.on_ctl_pdu(_pdu, BleDirection.MASTER_TO_SLAVE)
                    if pdu is not None:
                        self.send_pdu(reshape_pdu(pdu), self.__conn_handle)
                else:
                    self.send_pdu(reshape_pdu(_pdu), self.__conn_handle)

        if len(self.__pending_data_pdus) > 0:
            logger.debug("Sending pending PDUs to other half...")
            for _pdu in self.__pending_data_pdus:
                if self.__proxy is not None:
                    logger.debug("Calling proxy on_data_pdu with PDU %s...", _pdu)
                    pdu = self.__proxy.on_data_pdu(_pdu, BleDirection.SLAVE_TO_MASTER)
                    if pdu is not None:
                        self.send_pdu(reshape_pdu(pdu), self.__conn_handle, direction=BleDirection.SLAVE_TO_MASTER)
                else:
                    logger.debug("Directly sending PDU %s...", _pdu)
                    self.send_pdu(reshape_pdu(_pdu), self.__conn_handle)


    def on_ctl_pdu(self, pdu):
        """This method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Peripheral devices act as a slave, so we only forward master to slave
        messages to the stack.

        :param Packet pdu: Control PDU received
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            if self.__other_half is not None and self.__connected:
                if self.__proxy is not None:
                    pdu = self.__proxy.on_ctl_pdu(pdu, BleDirection.MASTER_TO_SLAVE)
                    if pdu is not None:
                        self.__other_half.forward_ctrl_pdu(pdu)
                else:
                    self.__other_half.forward_ctrl_pdu(pdu)


    def on_data_pdu(self, pdu):
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        :param Packet pdu: Data PDU received
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            if self.__other_half is not None and self.__connected:
                if self.__proxy is not None:
                    pdu = self.__proxy.on_data_pdu(pdu, BleDirection.MASTER_TO_SLAVE)
                    if pdu is not None:
                        self.__other_half.forward_data_pdu(pdu)
                else:
                    self.__other_half.forward_data_pdu(pdu)
            else:
                logger.error("client is not connected to proxy")


    def forward_ctrl_pdu(self, pdu):
        """Forward a control pdu to the target device.

        :param Packet pdu: Control PDU to forward
        """
        logger.info("Forwarding control PDU to central (%s)", str(self.__conn_handle))
        if self.__conn_handle is not None:
            return self.send_pdu(
                reshape_pdu(pdu),
                self.__conn_handle,
                direction=BleDirection.SLAVE_TO_MASTER
            )

        # Not connected, adding control PDU to pending control PDUs
        self.__pending_control_pdus.append(reshape_pdu(pdu))
        return True


    def forward_data_pdu(self, pdu):
        """Forward a data pdu to the target device.

        :param Packet pdu: Data PDU to forward
        """
        if self.__conn_handle is not None:
            logger.info("Forwarding data PDU to central (%s)", str(self.__conn_handle))
            return self.send_pdu(
                reshape_pdu(pdu),
                self.__conn_handle,
                direction=BleDirection.SLAVE_TO_MASTER
            )

        # Not connected, adding data PDU to pending data PDUs
        logger.info("Adding data PDU to pending PDUs")
        self.__pending_data_pdus.append(reshape_pdu(pdu))
        return True


class LowLevelCentral(Central):
    """Link-layer only Central implementation

    This class implements a Central role that is able to initiate a BLE connection
    to a target device and then forward all the control and data PDUs to the attached
    LowLevelPeripheral instance.

    No BLE stack is bound tho this Central role, only raw PDUs sent by the target
    device or received from the associated peripheral.
    """

    def __init__(self, proxy, device, connection_data=None):
        """Instantiate a LowLevelCentral object

        :param WhadDevice device: Underlying WHAD device to use.
        """
        super().__init__(device, existing_connection=connection_data)
        self.__connected = False
        self.__other_half = None
        self.__proxy = proxy


    def set_other_half(self, other_half):
        """Set the *other half*, the associated LowLevelPeripheral.

        :param LowLevelPeripheral other_half: Associated LowLevelPeripheral
        """
        self.__other_half = other_half


    def is_connected(self):
        """Determine if this Central device is connected to the target device.

        :rtype: bool
        :return: True if an active connection exists between the central device
                 and the target, False otherwise
        """
        return self.__connected


    def peripheral(self):
        return True


    def on_connected(self, connection_data):
        """Callback called when our central device is successfully connected to our target device

        :param connection_data: Connection data
        """
        # Call Central.on_connected()
        super().on_connected(connection_data)

        self.__connected = True
        if connection_data.conn_handle is None:
            self.__conn_handle = 0
        else:
            self.__conn_handle = connection_data.conn_handle


    def on_disconnected(self, disconnection_data):
        """Callback called when our central device has been disconnected from our target device
        """
        super().on_disconnected(disconnection_data)

        logger.info("target device has disconnected")
        self.__connected = False
        self.__conn_handle = None


    def on_ctl_pdu(self, pdu):
        """Callback called whenever a Control PDU has been received.

        This callback method then forwards PDU to the associated LowLevelPeripheral object that
        will handle it.

        :param Packet pdu: Received Control PDU
        """
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            if self.__other_half is not None and self.__connected:
                if self.__proxy is not None:
                    pdu = self.__proxy.on_ctl_pdu(pdu, BleDirection.SLAVE_TO_MASTER)
                    if pdu is not None:
                        self.__other_half.forward_ctrl_pdu(pdu)
                else:
                    self.__other_half.forward_ctrl_pdu(pdu)


    def on_data_pdu(self, pdu):
        """Callback called whenever a Data PDU has been received.

        This callback method then forwards PDU to the associated LowLevelPeripheral object that
        will handle it.

        :param Packet pdu: Received Data PDU
        """
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            if self.__other_half is not None and self.__connected:
                if self.__proxy is not None:
                    pdu = self.__proxy.on_data_pdu(pdu, BleDirection.SLAVE_TO_MASTER)
                    if pdu is not None:
                        self.__other_half.forward_data_pdu(pdu)
                else:
                    self.__other_half.forward_data_pdu(pdu)


    def forward_ctrl_pdu(self, pdu):
        """Forward a Control PDU to the connected device, if an active connection exists

        :param Packet pdu: Control PDU to send to the connected device
        """
        if self.__conn_handle is not None:
            return self.send_pdu(reshape_pdu(pdu), self.__conn_handle)

        # Error, proxy not connected
        logger.error("proxy is not connected to target device")
        return False

    def forward_data_pdu(self, pdu):
        """Forward a Data PDU to the connected device, if an active connection exists

        :param Packet pdu: Data PDU to send to the connected device
        """
        if self.__conn_handle is not None:
            return self.send_pdu(reshape_pdu(pdu), self.__conn_handle)

        # Error, proxy not connected
        logger.error("proxy is not connected to target device")
        return False


class LinkLayerProxy:
    """This class implements a GATT proxy that relies on two BLE-compatible
    WHAD devices to create a real BLE device that will proxify all the link-layer
    traffic to another device.
    """

    def __init__(self, proxy=None, target=None, adv_data=None, scan_data=None, bd_address=None,
                 spoof=False, random=False):
        """
        :param BLE proxy: BLE device to use as a peripheral (GATT Server)
        :param BLE target: BLE device to use as a central (GATT Client)
        :param AdvDataFieldList adv_data: Advertising data
        :param AdvDataFieldList scan_data: Scan response data
        :param str bd_address: BD address of target device
        """
        if proxy is None or target is None or bd_address is None:
            raise WhadDeviceNotFound

        if adv_data is None:
            self.__adv_data = AdvDataFieldList(
                AdvFlagsField(),
                AdvCompleteLocalName(b"BleProxy")
            )
        else:
            self.__adv_data = adv_data

        self.__scan_data = scan_data

        # Save both devices
        self.__proxy = proxy
        self.__central = None
        self.__listener = None
        self.__target = target
        self.__peripheral = None
        self.__target_bd_addr = bd_address
        self.__target_random=random
        self.__spoof = spoof


    @property
    def target(self):
        """Proxy target (central)
        """
        return self.__central


    def get_wireshark_monitor(self):
        """Attach a Wireshark monitor to the target device.

        :rtype: WiresharkMonitor
        """
        monitor_ws = WiresharkMonitor()
        monitor_ws.attach(self.__central)
        return monitor_ws


    def get_pcap_monitor(self, filename):
        """Attach a PCAP writer monitor to the target device.

        :rtype: PcapWriterMonitor
        """
        monitor_pcap = PcapWriterMonitor(filename)
        monitor_pcap.attach(self.__central)
        return monitor_pcap


    def close(self):
        """Close proxy
        """
        if self.__central is not None:
            self.__central.close()
        if self.__peripheral is not None:
            self.__peripheral.close()

    def start(self):
        """Start proxy

        The proxy device will be set as a peripheral
        """

        # First, connect our central device to our target device
        logger.info("create low-level central device ...")
        self.__central = LowLevelCentral(self, self.__target)
        self.__central.add_event_handler(self.on_central_event, CentralDisconnected)
        self.__central.lock()
        logger.info("connecting to target device ...")
        if self.__central.connect(self.__target_bd_addr, random=self.__target_random) is not None:
            logger.info("proxy is connected to target device, create our own device ...")

            # Once connected, we start our peripheral
            self.__peripheral = LowLevelPeripheral(
                self,
                self.__proxy,
                self.__adv_data,
                self.__scan_data,
                bd_address=self.__target_bd_addr,
                public=not self.__target_random
            )

            # Interconnect central and peripheral
            logger.info("proxy peripheral device created, interconnect with central ...")
            self.__peripheral.set_other_half(self.__central)
            self.__central.set_other_half(self.__peripheral)
            logger.info("central and peripheral devices are now interconnected")

            # Install peripheral event listener
            self.__listener = PeripheralEventListener(callback=self.on_periph_event)
            self.__peripheral.attach_event_listener(self.__listener)
            self.__listener.start()

            # Start advertising
            logger.info("starting advertising our proxy device")
            self.__peripheral.start()
            self.__central.unlock()
            logger.info("LinkLayerProxy instance is ready")

    def stop(self):
        """Stop proxy
        """
        if self.__listener is not None:
            self.__listener.stop()

        # Stop central
        self.__central.clear_event_handlers()
        self.__central.stop()

    def on_periph_event(self, event):
        """Handle peripheral events.
        """
        if isinstance(event, PeripheralEventConnected):
            """When a central is connected, update its mtu if not 23.
            """
            mtu = self.__central.get_mtu()
            if mtu != 23:
                self.__peripheral.set_mtu(mtu)
        elif isinstance(event, PeripheralEventDisconnected):
            """Notify proxy that peripheral has disconnected
            """
            self.on_disconnect()

    def on_central_event(self, event):
        """Central event handler
        """
        if isinstance(event, CentralDisconnected):
            # Central has disconnected, 
            if self.__peripheral.conn_handle is not None:
                self.__peripheral.disconnect(self.__peripheral.conn_handle)
                self.__peripheral.wait_disconnection()
                self.__peripheral.stop()
                self.__listener.stop()
            else:
                logger.debug("[LinkLayerProxy] peripheral not connected")

            # Reconnect to Central
            self.__central.stop()
            self.start()

    def on_connect(self):
        """This method is called when a client connects to the proxy.
        """
        logger.info("Client has just connected to our proxy")


    def on_disconnect(self):
        """This method is called when a client disconnects from the proxy.
        """
        logger.info("Client has just disconnected from our proxy")


    def on_ctl_pdu(self, pdu, direction):
        """Control PDU callback

        This method is called whenever a BLE control PDU is received. The returned
        PDU will be forwarded to the target device, or discarded if None is returned.

        :param Packet pdu: Scapy packet representing the BLE control PDU
        :return: A PDU to be sent to the target device or None to avoid forwarding.
        :rtype: Packet, None
        """
        logger.info("Received a Control PDU: %s (Direction: %d)", bytes(pdu).hex(), direction)
        return pdu


    def on_data_pdu(self, pdu, direction):
        """Data PDU callback

        This method is called whenever a BLE data PDU is received. The returned
        PDU will be forwarded to the target device, or discarded if None is returned.

        :param Packet pdu: Scapy packet representing the BLE data PDU
        :return: A PDU to be sent to the target device or None to avoid forwarding.
        :rtype: Packet, None
        """
        logger.info("Received a Data PDU: %s (Direction: %d)", bytes(pdu).hex(), direction)
        return pdu


#############################################
# GATT Proxy related classes
#############################################

class ImportedDevice(GenericProfile):
    """Device imported from JSON profile.
    """

    def __init__(self, proxy, target, from_json):
        super().__init__(from_json=from_json)
        self.__target = target
        self.__proxy = proxy


    def on_connect(self, conn_handle):
        """This method is called when a device connects to the GATT proxy, and will
        forward this event to the GATT proxy.
        """
        self.__proxy.on_connect(conn_handle)


    def on_disconnect(self, conn_handle):
        """This method is called when a device disconnects from the GATT proxy and
        forwards this event to the proxy itself.
        """
        self.__proxy.on_disconnect(conn_handle)


    def on_characteristic_read(self, service, characteristic, offset=0, length=0):
        """Callback method that handles a characteristic read operation.

        This method accesses the characteristic value and call a proxy-specific
        callback to let the user choose what should be done with this value.

        If the proxy callback raises a :class:`HookReturnValue` exception, the underlying
        GATT stack will take the provided value and return it to the client.

        If no exception is raised then the original characteristic value is returned.
        """
        try:
            # Get characteristic and read its value
            c = self.__target.get_characteristic(service.uuid, characteristic.uuid)
            value = c.read(offset=offset)

            # Call our proxy characteristic read hook
            self.__proxy.on_characteristic_read(
                service,
                characteristic,
                value,
                offset,
                length
            )

            # By default, return characteristic value
            raise HookReturnValue(value)
        except GattTimeoutException as gatt_error:
            logger.error("GATT timeout during characteristic read, return empty data")
            raise HookReturnValue(b'') from gatt_error
        except ConnectionLostException:
            logger.error("GATT connection lost while reading from characteristic")


    def on_characteristic_write(self, service, characteristic, offset=0, value=b'',
                                without_response=False):
        """Characteristic write hook

        This hook is called whenever a charactertistic is about to be written by a GATT
        client. If this method returns None, then the write operation will return an error.
        """
        c = None

        try:

            # Get target characteristic and write its value
            c = self.__target.get_characteristic(service.uuid, characteristic.uuid)

            self.__proxy.on_characteristic_write(
                service,
                characteristic,
                offset,
                value,
                without_response
            )

            # Write value to target device
            c.write(value, without_response=without_response)
        except HookReturnValue as write_override:
            c.write(write_override.value, without_response=without_response)
        except GattTimeoutException:
            logger.error("GATT timeout during characteristic write")
        except ConnectionLostException:
            logger.error("GATT connection lost while writing to characteristic")


    def on_characteristic_subscribed(self, service, characteristic, notification=False,
                                     indication=False):
        """Characteristic subscription hook.
        """
        try:
            c = self.__target.get_characteristic(service.uuid, characteristic.uuid)
            if notification and c is not None:
                # Forward callback
                def notif_cb(handle, value, indication=False):
                    try:
                        # Forward to proxy
                        self.__proxy.on_notification(
                            service,
                            characteristic,
                            value
                        )

                        # Update characteristic value
                        characteristic.value = value

                    except HookReturnValue as value_override:
                        # Override value if required
                        characteristic.value = value_override.value

                    except HookDontForward:
                        # Don't forward notification
                        pass
                logger.info("[proxy] subscribe to characteristic %s", characteristic.uuid)
                c.subscribe(callback=notif_cb, notification=True)
            elif indication and c is not None:
                # Forward callback
                def indicate_cb(handle, value, indication=True):
                    try:
                        # Forward to proxy hook.
                        self.__proxy.on_indication(
                            service,
                            characteristic,
                            value
                        )

                        # Update characteristic value
                        characteristic.value = value

                    except HookReturnValue as value_override:
                        # Override value if required
                        characteristic.value = value_override.value

                    except HookDontForward:
                        # Don't forward notification
                        pass

                logger.info("[proxy] subscribe to characteristic %s (indication)",
                            characteristic.uuid)
                c.subscribe(callback=indicate_cb, indication=True)

            else:
                logger.error("[proxy] cannot find characteristic %s", characteristic.uuid)

            # No action possible here (for now)
            self.__proxy.on_characteristic_subscribed(
                service,
                characteristic,
                notification=notification,
                indication=indication
            )
        except GattTimeoutException:
            logger.error("GATT timeout during characteristic subscribe")
        except ConnectionLostException:
            logger.error("GATT connection lost while unsubscribing from characteristic")


    def on_characteristic_unsubscribed(self, service, characteristic):
        """Characteristic unsubscription hook.
        """
        try:
            c = self.__target.get_characteristic(service.uuid, characteristic.uuid)
            c.unsubscribe()

            # No action possible here (for now)
            self.__proxy.on_characteristic_unsubscribed(
                service,
                characteristic
            )
        except GattTimeoutException:
            logger.error("GATT timeout during characteristic unsubscribe")
        except ConnectionLostException:
            logger.error("GATT connection lost while unsubscribing from characteristic")

    def on_mtu_changed(self, mtu: int):
        """MTU update callback.
        """
        self.__proxy.on_mtu_changed(mtu)


class GattProxy:
    """GATT Proxy
    """

    def __init__(self, proxy=None, target=None, adv_data=None, scan_data=None, bd_address=None,
                 spoof=False, profile=None, random=False):
        self.__central = None
        self.__peripheral = None
        self.__proxy_dev = proxy
        self.__target_dev = target
        self.__spoof = spoof
        self.__profile = profile
        if adv_data is None:
            self.__adv_data = AdvDataFieldList(
                AdvFlagsField(),
                AdvCompleteLocalName(b"BleProxy")
            )
        else:
            self.__adv_data = adv_data
        self.__scan_data = scan_data
        self.__target = None
        self.__target_bd_addr = bd_address
        self.__target_random = random
        self.__central_mtu = 23
        self.__listener = None

    @property
    def target(self):
        """Proxy target
        """
        return self.__target

    @property
    def central(self):
        """Central role
        """
        return self.__central

    @property
    def peripheral(self):
        """Peripheral role
        """
        return self.__profile

    def get_wireshark_monitor(self):
        """Attach a Wireshark monitor to the our proxy.

        :rtype: WiresharkMonitor
        """
        if self.__peripheral is not None:
            monitor_ws = WiresharkMonitor()
            monitor_ws.attach(self.__peripheral)
            return monitor_ws

        # No wireshark monitor attached
        return None


    def get_pcap_monitor(self, filename):
        """Attach a PCAP writer monitor to the target device.

        :rtype: PcapWriterMonitor
        """
        if self.__peripheral is not None:
            monitor_pcap = PcapWriterMonitor(filename)
            monitor_pcap.attach(self.__peripheral)
            return monitor_pcap

        # No PCAP monitor attached
        return None


    def on_connect(self, conn_handle: int):
        """Connection callback
        """
        logger.info("client connected to proxy (handle: %d)", conn_handle)


    def on_disconnect(self, conn_handle):
        """Disconnection callback
        """
        logger.info("client disconnected from proxy (handle: %d)", conn_handle)


    def on_characteristic_read(self, service, characteristic, value, offset=0, length=0):
        """This callback is called whenever a characteristic is read.

        :param Service service: Service object the target characteristic belongs to.
        :param Characteristic characteristic: Target characteristic object.
        :param bytes value: Characteristic value
        :param int offset: write offset
        :param int length: maximum read length for this characteristic
        """
        logger.info(" << Read characteristic %s: %s", characteristic.uuid, value)


    def on_characteristic_write(self, service, characteristic, offset=0, value=b'',
                                without_response=False):
        """This callback is called whenever a characteristic is written.

        Raise a :class:`HookReturnValue` exception to override the value that will be written
        in the target characteristic.

        Raise any other hook exception (:class:`HookReturnAccessDenied`,
        :class:`HookReturnNotFound`, :class:`HookReturnAuthentRequired` or
        :class:`HookReturnAuthorRequired`) to force the proxy
        to return a specific error to the initiator device.

        :param Service service: Service object the target characteristic belongs to.
        :param Characteristic characteristic: Target characteristic object.
        :param int offset: write offset
        :param bytes value: value to write into this characteristic
        :param bool without_response: True if write operation does not require a response,
                                      False otherwise (default: False)
        """
        logger.info(" >> Write characteristic %s with value %s at offset %d",
                    characteristic.uuid, value, offset)


    def on_characteristic_subscribed(self, service, characteristic, notification=False,
                                     indication=False):
        """This callback is called whenever a characteristic is subscribed to for
        notification or indication.

        :param Service service: Service object the target characteristic belongs to.
        :param Characteristic characteristic: Target characteristic object.
        :param bool notification: Set to True to subscribe for notification
        :param bool indication: Set to True to subscribe to indication
        """
        logger.info(" ** Subscribed to characteristic %s from service %s",
                    characteristic.uuid, service.uuid)


    def on_characteristic_unsubscribed(self, service, characteristic):
        """This callback is called whenever a characteristic is unsubscribed.

        :param Service service: Service object the target characteristic belongs to.
        :param Characteristic characteristic: Target characteristic object.
        """
        logger.info(" ** Unsubscribed to characteristic %s from service %s",
                    characteristic.uuid, service.uuid)


    def on_notification(self, service, characteristic, value):
        """This callback is called whenever a notification is received.
        """
        logger.info(" == notification for characteristic %s from service %s: %s",
                    characteristic.uuid, service.uuid, value)


    def on_indication(self, service, characteristic, value):
        """This callback is called whenever a notification is received.
        """
        logger.info(" == indication for characteristic %s from service %s: %s",
                    characteristic.uuid, service.uuid, value)

    def on_mtu_changed(self, mtu: int):
        """MTU has been updated
        """
        logger.info("== MTU changed to %d", mtu)

    def on_central_event(self, event):
        """Handle Central events.
        """
        if isinstance(event, CentralDisconnected):
            # Central has disconnected, kill peripheral
            if self.__peripheral.conn_handle is not None:
                self.__peripheral.disconnect(self.__peripheral.conn_handle)

            # Reconnect to Central using the already discovered GATT profile
            self.__peripheral.stop()
            self.__central.stop()
            self.__profile = self.__target_profile
            self.start()

    def start(self):
        """Start our GATT Proxy
        """
        logger.info("create our central device")
        self.__central = Central(self.__target_dev, from_json=self.__profile)
        self.__central.add_event_handler(self.on_central_event)
        logger.info("connect to target device (random:%s)", self.__target_random)
        self.__target = self.__central.connect(self.__target_bd_addr, random=self.__target_random)
        if self.__target is not None:
            if self.__profile is not None:
                logger.info("use the provided profile (json) ...")
                self.__target_profile = self.__profile
            else:
                logger.info("connected to target device, discover services and characteristics ...")
                self.__target.discover()
                logger.info("services and characs discovered")
                self.__target_profile = self.__target.export_json()

            # Once connected, we start our peripheral
            self.__central_mtu = self.__central.get_mtu()
            logger.debug("[GattProxy] central mtu: %d", self.__central_mtu)
            logger.info("create a peripheral with similar profile ...")
            self.__profile = ImportedDevice(
                    self,
                    self.__target,
                    self.__target_profile
            )

            # Create a peripheral with the target device address if possible
            # If not, the device will take its own default address.
            self.__peripheral = Peripheral(self.__proxy_dev, profile=self.__profile,
                adv_data=self.__adv_data,
                scan_data=self.__scan_data,
                bd_address=self.__target_bd_addr,
                public=not self.__target_random
            )
            
            # Attach peripheral listener
            self.__listener = PeripheralEventListener(callback=self.on_periph_event)
            self.__peripheral.attach_event_listener(self.__listener)
            self.__listener.start()

            self.__peripheral.enable_peripheral_mode(adv_data=self.__adv_data)

            # Start advertising
            logger.info("starting advertising")
            self.__peripheral.start()
            logger.info("GattProxy instance is ready")

    def stop(self):
        """Stop proxy
        """
        if self.__listener is not None:
            self.__listener.stop()

        # Remove event handlers
        self.central.clear_event_handlers()
        
        # Disconnect central and peripheral
        if self.__target.conn_handle is not None:
            self.__central.disconnect(self.__target.conn_handle)
        self.__central.stop()
        if self.__peripheral is not None:
            if self.__peripheral.conn_handle is not None:
                self.__peripheral.disconnect(self.__peripheral.conn_handle)
            self.__peripheral.stop()

    def on_periph_event(self, event):
        """Handle peripheral events.
        """
        if isinstance(event, PeripheralEventConnected):
            """When a central is connected, update its mtu if not 23.
            """
            self.__central_mtu = self.__central.get_mtu()
            logger.debug("[GattProxy] central mtu: %d", self.__central_mtu)
            if self.__central_mtu != 23:
                logger.debug("[GattProxy] Setting peripheral MTU to %d", self.__central_mtu)
                self.__peripheral.set_mtu(self.__central_mtu)