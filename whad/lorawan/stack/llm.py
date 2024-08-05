"""
LoRaWAN Gateway stack link-layer manager
"""
from time import sleep, time
from binascii import hexlify
from random import randint
from whad.lorawan.stack.mac import LWMacLayer
from whad.common.stack import LayerState, Layer, alias, source, state,instance
from whad.scapy.layers.lorawan import MACPayloadUplink, PHYPayload, JoinAccept, JoinRequest, MACPayloadDownlink
from whad.lorawan.crypto import MIC, derive_appskey, derive_nwkskey, encrypt_packet, decrypt_packet
from whad.lorawan.helpers import EUI

import logging
logger = logging.getLogger(__name__)

class LWGwLinkLayerState(LayerState):

    def __init__(self):
        super().__init__()

        # Keep track of connections
        self.connections = {}

        # Normal delays (1 second and then 2 seconds)
        self.rx_delay1 = 1.0
        self.rx_delay2 = 2.0

        # Join delays (5 seconds and then 6 seconds)
        self.join_delay1 = 5.0
        self.join_delay2 = 6.0

    def has_devaddr(self, dev_addr : int) -> bool:
        """Check if a device address is already registered

        :param dev_addr: Device address
        :type dev_addr: int

        :returns: True if device address is known, False otherwise.
        :rtype: bool
        """
        return (dev_addr in self.connections)

    def register_connection(self, dev_addr : int, dev_eui : EUI = None, mac_node : str = None,
                            appskey : bytes = None, nwkskey : bytes = None, timestamp : float = None):
        """Register a device connection.

        Keeps track of MAC instance name associated with the device as well as the
        LoRaWAN 1.0 encryption keys.


        :param dev_addr: Device address
        :type dev_addr: int
        :param mac_node: MAC contextual layer instance name
        :type mac_node: str
        :param appskey: Application Session key
        :type appskey: bytes
        :param nwkskey: Network Session key
        :type nwkskey: bytes
        """
        if dev_addr not in self.connections:
            self.connections[dev_addr] = {
                'dev_eui': str(dev_eui),
                'mac_node': mac_node,
                'appskey': appskey,
                'nwkskey': nwkskey,
                'timestamp': timestamp
            }

    def update_connection(self, dev_addr : int, timestamp : float = None):
        """Update connection timestamp


        :param dev_addr: Device network address
        :type dev_addr: int
        :param timestamp: Timestamp in seconds
        :type timestamp: float
        """
        connection = self.get_connection(dev_addr)
        if connection is not None:
            if timestamp is not None:
                connection['timestamp'] = timestamp

    def get_connection(self, dev_addr : int) -> dict:
        """Retrieve a connection associated with a given
        device address.

        :param dev_addr: device address
        :type dev_addr: int
        :returns: connection data
        :rtype: dict
        """
        if self.has_devaddr(dev_addr):
            return self.connections[dev_addr]
        else:
            return None


    def get_connection_from_node(self, mac_node : str) -> dict:
        """Get connection data from MAC layer node

        :param mac_node: MACLayer instance name
        :type mac_node: str
        
        :returns: Connection data or None if not found
        :rtype: dict
        """
        for dev_addr in self.connections:
            if self.connections[dev_addr]['mac_node'] == mac_node:
                return self.connections[dev_addr]
        return None

@alias('ll')
@state(LWGwLinkLayerState)
class LWGwLinkLayer(Layer):
    """
    LoRaWAN Gateway link-layer manager.

    This layer handles the LoRaWAN over-the-air activation
    as well as encryption/decryption of incoming and outgoing
    communications.
    """

    def configure(self, options={}):
        """Configure Link layer state
        """
        # Process options
        if 'rx_delay1' in options:
            self.state.rx_delay1 = options['rx_delay1']
        if 'rx_delay2' in options:
            self.state.rx_delay2 = options['rx_delay2']
        if 'join_delay1' in options:
            self.state.join_delay1 = options['join_delay1']
        if 'join_delay2' in options:
            self.state.join_delay2 = options['join_delay2']

    def generate_devaddr(self) -> int:
        """Generate a free device network address

        :returns: Attributed device network address
        :rtype: int
        """
        nok = True
        while nok:
            dev_addr = randint(0, 0xffffff)
            nok = self.state.has_devaddr(dev_addr)
        return dev_addr

    def on_join_request(self, frame : PHYPayload):
        """Process an incoming Join Request

        :param frame: LoRaWAN frame
        :type frame: PHYPayload
        """
        
        # Retrieve APPKey and APPEUI
        self.appkey = self.get_layer('phy').get_appkey()
        self.app_eui = self.get_layer('phy').get_appeui()

        logger.debug('processing a JoinRequest ...')
        # Check the Join Request against our APPKEY/APPEUI
        join_req = frame.getlayer(JoinRequest)
        exp_mic = MIC(self.appkey, bytes(frame)[:-4])
        if exp_mic == bytes(frame)[-4:]:
            logger.debug('JoinRequest MIC is valid')
            # Retrieve APP EUI amd DEV EUI from packet
            app_eui = EUI(join_req.join_eui)
            dev_eui = EUI(join_req.dev_eui)

            # Make sure APP EUI and DEV EUI are valid
            if app_eui == self.app_eui and self.get_layer('phy').is_device_allowed(dev_eui):

                # Device is allowed and application is known
                logger.debug('Device with EUI %s is allowed to join with app EUI %s' % (
                    dev_eui,
                    app_eui
                ))

                # Add node to our list of connections
                dev_addr = self.generate_devaddr()
                join_nonce = randint(0, 0xffffff)

                # Derive appskey and nwkskey
                dev_appskey = derive_appskey(self.appkey, join_nonce, 0x13, join_req.dev_nonce)
                dev_nwkskey = derive_nwkskey(self.appkey, join_nonce, 0x13, join_req.dev_nonce)

                # Instanciate a node for our connection
                conn_mac = self.instantiate(LWMacLayer)
                conn_mac.set_devaddr(dev_addr)

                # Save node information
                self.state.register_connection(
                    dev_addr,
                    dev_eui,
                    conn_mac.name,
                    dev_appskey,
                    dev_nwkskey,
                    time()
                )

                # Notify connector we got a connection
                self.get_layer('phy').on_device_joined(
                    dev_eui,
                    dev_addr,
                    dev_appskey,
                    dev_nwkskey
                )

                # Craft join accept                   
                join_accept = PHYPayload()/JoinAccept(
                    join_nonce = join_nonce,
                    home_netid=0x13,
                    dev_addr = dev_addr
                )

                # Encrypt response
                enc_ja = encrypt_packet(join_accept, appkey=self.appkey)

                # Send response
                ts = frame.metadata.timestamp/1000000.
                logger.debug('JoinRequest timestamp: %f' % ts)
                logger.debug('will send JoinAccept at %f' % (ts + self.state.join_delay1))
                self.send('phy', enc_ja, timestamp=ts + self.state.join_delay1)
                sleep(self.state.join_delay1 + 0.5)
            else:
                if app_eui != self.app_eui:
                    logger.debug('Application %s is requested, expected application EUI %s' % (
                        app_eui,
                        self.app_eui
                    ))
                else:
                    logger.debug('Device with EUI %s is not allowed to access application EUI %s' % (
                        dev_eui,
                        app_eui
                    ))
        else:
            logger.debug(
                'JoinRequest MIC is wrong (got %s instead of %s)' % (
                hexlify(bytes(frame)[-4:]),
                hexlify(exp_mic)
            ))

    def add_provisioned_device(self, dev_addr : int, dev_eui : str, appskey : bytes,
                               nwkskey : bytes, upcount : int, dncount : int):
        """Add a pre-provisioned device to our current state.

        :param dev_addr: Device network address
        :type dev_addr: int
        :param dev_eui: Device EUI
        :type dev_eui: str
        :param dev_appskey: Device application session key
        :type dev_appskey: bytes
        :param dev_nwkskey: Device network encryption session key
        :type dev_nwkskey: bytes
        """
        logger.debug('add a pre-provisioned device (address 0x%08x, eui: %s)' % (
            dev_addr, dev_eui
        ))

        # Instanciate a node for our connection
        conn_mac = self.instantiate(LWMacLayer)
        conn_mac.set_devaddr(dev_addr)
        logger.debug('created a LWMACLayer instance for device: %s' % conn_mac.name)

        # Set uplink/downlink frame counters
        conn_mac.set_up_counter(upcount)
        conn_mac.set_down_counter(dncount)

        # Save node information
        self.state.register_connection(
            dev_addr,
            dev_eui,
            conn_mac.name,
            appskey,
            nwkskey,
        )

    def on_rejoin_request(self, rejoin_request):
        """Process a Rejoin Request

        Not implemented for now :(
        """
        pass

    def on_unconfirmed_data_up(self, unc_data_up : PHYPayload):
        """Process an unconfirmed data up.

        :param unc_data_up: LoRaWAN unconfirmed data up frame
        :type unc_data_up: PHYPayload
        """
        mac_layer = unc_data_up.getlayer(MACPayloadUplink)

        # Get the device address and check if it is known and that we have
        # at least seen one uplink packet
        connection = self.state.get_connection(mac_layer.dev_addr)
        if connection is not None and connection['timestamp'] is not None:
            # Update connection last packet timestamp
            ts = unc_data_up.metadata.timestamp/1000000.
            self.state.update_connection(
                mac_layer.dev_addr,
                ts
            )

            # Decrypt frame with the corresponding keys
            dec_unc_data_up = decrypt_packet(
                unc_data_up,
                appskey=connection['appskey'],
                nwkskey=connection['nwkskey']
            )

            # Forward the decrypted packet to MAC layer
            self.send(
                connection['mac_node'],
                dec_unc_data_up.getlayer(MACPayloadUplink),
                confirmed=False
            )
        else:
            logger.debug('Device address 0x%08x is not known' % mac_layer.dev_addr)

    def on_confirmed_data_up(self, conf_data_up : PHYPayload):
        """Process a confirmed data up.

        Not supported yet.

        :param conf_data_up: LoRaWAN confirmed data up frame
        :type conf_data_up: PHYPayload
        """
        pass


    @source('phy')
    def on_phy_frame(self, frame: PHYPayload):
        """Process a frame coming from our gateway PHY layer.

        :param frame: LoRaWAN frame
        :type frame: PHYPayload
        """
        # Is it a join request ?
        if frame.mtype == 0:
            self.on_join_request(frame)
        # Or an unconfirmed data up ?
        elif frame.mtype == 2:
            self.on_unconfirmed_data_up(frame)
        # Or a confirmed data up ?
        elif frame.mtype == 4:
            self.on_confirmed_data_up(frame)
        # Or a rejoin request ?
        elif frame.mtype == 6:
            self.on_rejoin_request(frame)

    @instance('mac')
    def on_mac_response(self, inst_name : str, frame : MACPayloadDownlink, confirmed : bool = False):
        """Send downlink message to remote device.

        :param inst_name: Name of the MAC instance that called this method
        :type inst_name: str
        :param frame: LoRaWAN downlink MAC frame to send
        :type frame: MACPayloadDownlink
        :param confirmed: Confirmed downlink frame must be sent
        :type confirmed: bool
        """
        # Find node from instance name
        connection = self.state.get_connection_from_node(inst_name)
        if connection is not None:
            logger.debug('[llm] MAC instance %s resolved to device eui %s' % (
                inst_name, connection['dev_eui']
            ))

            # Craft downlink frame
            packet = PHYPayload()/frame
            if confirmed:
                packet.mtype = 5
            else:
                packet.mtype = 3
            
            # Encrypt message for our target device           
            enc_pkt = encrypt_packet(
                packet,
                appskey=connection['appskey'],
                nwkskey=connection['nwkskey']
            )

            # Send response after rx1 delay
            self.send(
                'phy',
                enc_pkt,
                timestamp=connection['timestamp'] + self.state.rx_delay1
            )
            sleep(self.state.rx_delay1 + 0.5)
        else:
            logger.debug('[llm] MAC instance %s not found' % inst_name)

    def on_data_received(self, dev_addr : int, data : bytes, upcount : int = 0):
        """Report data reception to phy

        :param dev_addr: Device network address
        :type dev_addr: int
        :param data: Data received
        :type data: bytes
        :param upcount: Uplink frame counter
        :type upcount: int
        """
        connection = self.state.get_connection(dev_addr)
        if connection is not None:
            # Connection found, report to PHY
            return self.get_layer('phy').on_data_received(
                connection['dev_eui'],
                dev_addr,
                data,
                upcount
            )
        else:
            logger.debug('[llm][on_data_received] Device address 0x%08x not found' % dev_addr)
            return None