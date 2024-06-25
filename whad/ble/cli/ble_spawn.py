"""Bluetooth Low Energy emulation tool

This utility will configure a compatible whad device to connect to a given
BLE device, and chain this with another tool.

"""
import json
import sys
from threading import Thread
from time import sleep

from scapy.layers.bluetooth4LE import BTLE_DATA, BTLE_CTRL

from whad.device import WhadDevice, PacketProcessor
from whad.device.unix import UnixSocketProxy, UnixSocketServerDevice, UnixConnector
from whad.cli.app import CommandLineDevicePipe

from whad.hub.ble.bdaddr import BDAddress
from whad.ble.connector import Central
from whad.ble.exceptions import PeripheralNotFound
from whad.ble.connector import Peripheral, BLE


import logging
logger = logging.getLogger(__name__)

def reshape_pdu(pdu):
    """This function remove any SN/NESN/MD bit as it is usually handled by
    the WHAD BLE-compatible dongle. Some BLE controllers and integrated stacks
    do not like to get PDUs with these bits set.

    :param Packet pdu: Bluetooth LE packet to process
    :return Packet: Clean Bluetooth LE packet
    """
    metadata = pdu.metadata
    btle_data = pdu.getlayer(BTLE_DATA)
    payload = btle_data.payload
    pkt = BTLE_DATA(
        LLID=btle_data.LLID,
        len=len(payload)
    )/payload
    pkt.metadata = metadata
    return pkt

class BlePacketProcessor(PacketProcessor):

    def __init__(self, conn_handle, input_iface, output_iface):
        super().__init__(input_iface, output_iface)
        self.__conn_handle = conn_handle

    def on_ingress_packet(self, packet):
        """Rewrite connection handle
        """
        logger.info('[ble-spawn] incoming packet processed')
        packet.metadata.connection_handle = self.__conn_handle
        super().on_ingress_packet(reshape_pdu(packet))
        

class BleLLProxy(Peripheral):
    """Proxy for peripheral.

    This class will create a Peripheral and will forward the following events
    to its associated `proxy` class:

    - Device connection to our peripheral BLE device
    - Device disconnection
    - Packet received from a central device connected to our peripheral
    """
    def __init__(self, interface, proxy, adv_data: bytes, scan_data: bytes):
        super().__init__(interface, adv_data=adv_data, scan_data=scan_data)
        self.__proxy = proxy

    def on_connected(self, connection_data):
        """Process connection event.
        """
        self.__proxy.on_connected(connection_data)
        return super().on_connected(connection_data)
    
    def on_disconnected(self, disconnection_data):
        """Process disconnection event.
        """
        self.__proxy.on_disconnected(disconnection_data)
        return super().on_disconnected(disconnection_data)

    def on_packet(self, packet):
        """Process incoming packet.
        """
        self.__proxy.on_rx_packet(packet)

class UnixSocketBlePacketProxy(BLE):
    """This class implements a wrapper that allows to notify a specific
    object that a packet has been sent.
    """

    def __init__(self, proxy, device):
        super().__init__(device)
        self.__proxy = proxy

    def on_packet(self, packet):
        """Process outgoing packet.
        """
        self.__proxy.on_tx_packet(packet)

class BleSpawnApp(CommandLineDevicePipe):
    """Bluetooth Low Energy device spawning tool.
    """

    MODE_END_CHAIN = 0
    MODE_START_CHAIN = 1

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy device emulation tool',
            interface=True,
            commands=False
        )

        self.add_argument(
            '--profile',
            '-p',
            dest='profile',
            help='Use a saved device profile'
        )   

        self.__mode = ''
        self.input_conn_handle = None
        self.output_conn_handle = None

    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.interface is not None:

                if self.args.profile is not None:
                    
                    # Load file content
                    profile_json = open(self.args.profile,'rb').read()
                    profile = json.loads(profile_json)
                    adv_data = bytes.fromhex(profile["devinfo"]["adv_data"])
                    scan_rsp = bytes.fromhex(profile["devinfo"]["scan_rsp"])

                    # If stdin is piped, we are supposed to advertise a device and
                    # proxify once connected
                    if self.is_stdin_piped() and not self.is_stdout_piped():
                        # We create a peripheral that will send all packets to our input interface
                        self.__mode = self.MODE_END_CHAIN
                        self.create_input_proxy(adv_data, scan_rsp)

                    # Else if stdout is piped, we are supposed to advertise a device
                    # and proxify when connected
                    elif self.is_stdout_piped() and not self.is_stdin_piped():
                        # We create a peripheral that will proxy all messages
                        self.__mode = self.MODE_START_CHAIN
                        self.create_output_proxy(adv_data, scan_rsp)
                    else:
                        self.error('Tool must be piped to another WHAD tool.')
                else:
                    self.error('You need to specify a profile file with option --profile.')
            else:
                self.error('You need to specify an interface with option --interface.')

        except KeyboardInterrupt as keybd:
            self.warning('ble-spawn stopped (CTL-C)')

        # Launch post-run tasks
        self.post_run()

    def create_input_proxy(self, adv_data: bytes, scan_data: bytes):
        """Configure our hardware to advertise a BLE peripheral, and once
        a central device is connected relay all packets to our input_interface.
        """
        self.input_conn_handle = int(self.args.conn_handle)

        # Create our peripheral
        '''
        self.proxy = BleLLProxy(
            WhadDevice.create(self.args.interface),
            self,
            adv_data,
            scan_data
        )
        self.proxy.start()
        
        # Loop on our input interface to dispatch packets
        self.packet_source = UnixSocketBlePacketProxy(self, self.input_interface)
        '''

        peripheral = Peripheral(self.interface, adv_data=adv_data, scan_data=scan_data)
        unix_client = UnixConnector(self.input_interface)
        pproc = PacketProcessor(unix_client, peripheral)

        # Loop
        while True:
            sleep(1)

    def on_connected(self, connection_data):
        if self.__mode == self.MODE_END_CHAIN:
            # Save output connection handle
            self.output_conn_handle = connection_data.conn_handle
            # Save current connection info
            self.connection = connection_data
        else:
            # Save input connection handle
            self.input_conn_handle = connection_data.conn_handle
            
            # Save current connection info
            self.connection = connection_data
            
            # Extract connection data and start a proxy

            metadata = {         
            'domain':'ble',
            'conn_handle': connection_data.conn_handle,
            'initiator_bdaddr':str(BDAddress(connection_data.initiator)),
            'initiator_addrtype':connection_data.init_addr_type,
            'target_bdaddr':str(BDAddress(connection_data.advertiser)),
            'target_addrtype':connection_data.adv_addr_type,
            }
            sys.stderr.write(str(metadata))


            self.proxy = UnixSocketProxy(self.interface, metadata)
            self.proxy.start()
            self.proxy.join()


    def on_disconnected(self, disconnection_data):
        pass

    def on_rx_packet(self, packet):
        """Process incoming packet (from connected central)
        """
        if self.__mode == self.MODE_END_CHAIN:
            if self.input_conn_handle is not None:
                packet.metadata.connection_handle = self.input_conn_handle
                self.packet_source.send_packet(packet)
        else:
            if self.input_conn_handle is not None:
                packet.metadata.connection_handle = self.input_conn_handle
                self.target.send_packet(packet)

    def on_tx_packet(self, packet):
        """Process outgoing packet (from input device)
        """
        if self.__mode == self.MODE_END_CHAIN:
            if self.output_conn_handle is not None:
                packet.metadata.connection_handle = self.output_conn_handle
                self.proxy.send_packet(packet)
        else:
            if self.output_conn_handle is not None:
                packet.metadata.connection_handle = self.output_conn_handle
                self.proxy.send_packet(packet)

    def create_output_proxy(self, adv_data, scan_data):
        """Create an output proxy that will relay packets from our emulated BLE
        peripheral to a chained tool.
        """
        
        # Create our peripheral
        peripheral = Peripheral(self.interface, adv_data=adv_data, scan_data=scan_data)

        # Wait for our peripheral to receive a connection
        peripheral.wait_connection()

        # Define our packet processor

        # Once we have a connection, create a Unix socket server device and wait
        # for a client to connect to our unix socket server
        unix_server_device = UnixSocketServerDevice(parameters={'domain':'ble'})
        unix_server_device.open()

        # Bridge our two devices with a packet processor.
        pproc = BlePacketProcessor(peripheral.conn_handle, self.interface, unix_server_device)

        while True:
            sleep(1)

    def connect_target(self, bdaddr, random_connection_type=False):
        """Connect to our target device
        """
        # Make sure the bd address is valid
        if BDAddress.check(bdaddr):
            # Configure our interface
            central = Central(self.interface)

            # Spoof source BD address if required
            if self.args.bdaddr_pub_src is not None:
                self.set_bd_address(central, self.args.bdaddr_pub_src, public=True)
            elif self.args.bdaddr_rand_src is not None:
                self.set_bd_address(central, self.args.bdaddr_rand_src, public=False)

            # Connect to our target device
            try:
                periph = central.connect(bdaddr, random_connection_type)

                # Get peers
                logger.info('local_peer: %s' % central.local_peer)

                # Connected, starts a Unix socket proxy that will relay the underlying
                # device WHAD messages to the next tool.
                proxy = UnixSocketProxy(self.interface, {
                    'domain':'ble',
                    'conn_handle':periph.conn_handle,
                    'initiator_bdaddr':str(central.local_peer),
                    'initiator_addrtype':str(central.local_peer.type),
                    'target_bdaddr':str(central.target_peer),
                    'target_addrtype': str(central.target_peer.type)
                })
                proxy.start()
                proxy.join()
            except PeripheralNotFound as not_found:
                # Could not connect
                self.error('Cannot connect to %s' % bdaddr)
            finally:
                central.stop()
        else:
            self.error('Invalid BD address: %s' % bdaddr)


def ble_spawn_main():
    app = BleSpawnApp()
    app.run()
