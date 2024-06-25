"""Bluetooth Low Energy connect tool

This utility will configure a compatible whad device to connect to a given
BLE device, and chain this with another tool.

"""
from time import sleep
from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble import SendBlePdu, SendBleRawPdu, Direction
from whad.cli.app import CommandLineDevicePipe
from whad.ble.connector import Central
from whad.device.unix import UnixSocketProxy, UnixSocketConnector, UnixConnector, UnixSocketServerDevice
from whad.device import PacketProcessor
from whad.ble.exceptions import PeripheralNotFound
from whad.ble import BLE
from whad.hub.ble import BlePduReceived, BleRawPduReceived

from scapy.layers.bluetooth4LE import BTLE_DATA, BTLE_CTRL

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

    #def on_inbound_packet(self, packet):
    #    logger.debug('[ble-connect] changed connection handle to %d' % self.__conn_handle)
    #    packet.metadata.connection_handle = self.__conn_handle
    #    return packet
    

class UnixSocketBlePacketProxy(UnixSocketConnector):
    """This class implements a wrapper that allows to notify a specific
    object that a packet has been sent.
    """

    def __init__(self, proxy, device):
        super().__init__(device)
        self.__proxy = proxy

    def on_packet(self, packet):
        """Process outgoing packet.
        """
        packet.show()
        if isinstance(packet, BlePduReceived) or isinstance(packet, BleRawPduReceived):
            self.__proxy.on_tx_packet(packet)

class BleLLProxy(Central):
    """Proxy for central.

    This class will create a Crentral and will forward the following events
    to its associated `proxy` class:

    - Device connection to our peripheral BLE device
    - Device disconnection
    - Packet received from a central device connected to our peripheral
    """
    def __init__(self, interface, proxy):
        super().__init__(interface)
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
        if BTLE_DATA in packet:
            self.__proxy.on_rx_packet(packet)

class BleConnectApp(CommandLineDevicePipe):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy connect tool',
            interface=True,
            commands=False
        )

        self.add_argument('bdaddr', metavar='BDADDR', help='Target device BD address')
        self.add_argument(
            '--spoof-public',
            metavar='PUB_BD_ADDR',
            dest='bdaddr_pub_src',
            default=None,
            help='Spoof a public BD address'
        )

        self.add_argument(
            '--spoof-random',
            metavar='RAND_BD_ADDR',
            dest='bdaddr_rand_src',
            default=None,
            help='Spoof a random BD address'
        )

        # Add an optional random type argument
        self.add_argument(
            '-r',
            '--random',
            dest='random',
            action='store_true',
            default=False,
            help='Use a random connection type'
        )


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.interface is not None:
                # Make sure we are piped to another tool
                if self.is_stdout_piped() and not self.is_stdin_piped():
                    # Connect to the target device
                    self.connect_target(self.args.bdaddr, self.args.random)
                elif self.is_stdin_piped() and not self.is_stdout_piped():
                    # Connect to the target device once the previous tool
                    # gives us a unix socket.
                    self.connect_target_and_proxify(self.args.bdaddr, self.args.random)
                else:
                    self.error('Tool must be piped to another WHAD tool.')
            else:
                self.error('You need to specify an interface with option --interface.')

        except KeyboardInterrupt as keybd:
            self.warning('ble-connect stopped (CTL-C)')

        # Launch post-run tasks
        self.post_run()

    def set_bd_address(self, central: Central, bdaddr: str, public=True):
        """Set central BLE address
        """
        # Make sure it is a valid BD address
        if BDAddress.check(bdaddr):
            # Set the BD address
            if not central.set_bd_address(bdaddr, public=public):
                self.warning('Cannot spoof BD address, please make sure your WHAD interface supports this feature.')
        else:
            self.error('Invalid spoofed BD address: %s' % bdaddr)


    def connect_target_and_proxify(self, bdaddr, random_connection_type=False):
        """Connect to our target device and relay packets between input interface
        and our target.
        """
        # Make sure the bd address is valid
        if BDAddress.check(bdaddr):

            print('create central')
            central = Central(self.interface)

            # Spoof source BD address if required
            if self.args.bdaddr_pub_src is not None:
                self.set_bd_address(central, self.args.bdaddr_pub_src, public=True)
            elif self.args.bdaddr_rand_src is not None:
                self.set_bd_address(central, self.args.bdaddr_rand_src, public=False)

            # Connect to our target device
            try:
                print('connect to peripheral')
                periph = central.connect(bdaddr, random_connection_type)

                # Configure our interface
                print('create a proxy for our peripheral')
                self.packet_source = BleLLProxy(self.interface, self)
                
                # Create a proxy to monitor packets coming from our target
                #print('create a unix socket proxy')
                #self.packet_source = UnixSocketBlePacketProxy(self, self.input_interface)
                #self.packet_source.serve()
                #self.packet_source = UnixSocketClientConnector(self.input_interface)
                self.proxy = UnixConnector(self.input_interface)
                
                #self.packet_source = PacketMonitor(self.packet_source)


                while True:
                    sleep(1)

            except PeripheralNotFound as not_found:
                # Could not connect
                self.error('Cannot connect to %s' % bdaddr)
            finally:
                self.proxy.stop()


    def on_connected(self, connection_data):
        pass

    def on_disconnected(self, disconnection_data):
        pass

    def on_tx_packet(self, packet):
        """Forward packet coming from our input device to our target device.
        """
        print('tx packet, send to unix client')
        packet.show()
        self.packet_source.send_packet(packet)

    def on_rx_packet(self, packet):
        """Forward packet coming from our connected device to our input
        interface.
        """
        packet.show()
        print(packet.metadata)
        print('[ble-connect] rx packet, send to unix client')
        self.proxy.send_packet(reshape_pdu(packet))

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
                """
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
                
                """
                proxy = UnixConnector(UnixSocketServerDevice(parameters={
                    'domain':'ble',
                    'conn_handle':periph.conn_handle,
                    'initiator_bdaddr':str(central.local_peer),
                    'initiator_addrtype':str(central.local_peer.type),
                    'target_bdaddr':str(central.target_peer),
                    'target_addrtype': str(central.target_peer.type)
                }))
                pproc = BlePacketProcessor(periph.conn_handle, central, proxy)
                #if proxy.support_raw_pdu():
                #    logger.error('proxy does support raw PDU')

                while True:
                    sleep(1)
                

                
            except PeripheralNotFound as not_found:
                # Could not connect
                self.error('Cannot connect to %s' % bdaddr)
            finally:
                central.stop()
        else:
            self.error('Invalid BD address: %s' % bdaddr)


def ble_connect_main():
    app = BleConnectApp()
    app.run()
