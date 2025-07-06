"""
Bluetooth LE Stack Link-layer Manager
"""
import logging
from struct import pack
from random import randint
from threading import Lock
from typing import Tuple

from scapy.layers.bluetooth4LE import *

from whad.common.stack import Layer, alias, source, state, LayerState, instance
from whad.ble.stack.l2cap import L2CAPLayer
from whad.ble.crypto import LinkLayerCryptoManager, generate_random_value, e
from whad.hub.ble import BDAddress

logger = logging.getLogger(__name__)

CONNECTION_UPDATE_REQ = 0x00
CHANNEL_MAP_REQ = 0x01
TERMINATE_IND = 0x02
ENC_REQ = 0x03
ENC_RSP = 0x04
START_ENC_REQ = 0x05
START_ENC_RSP = 0x06
UNKNOWN_RSP = 0x07
FEATURE_REQ = 0x08
FEATURE_RSP = 0x09
PAUSE_ENC_REQ = 0x0A
PAUSE_ENC_RSP = 0x0B
VERSION_IND = 0x0C
REJECT_IND = 0x0D
SLAVE_FEATURE_REQ = 0x0E
CONNECTION_PARAM_REQ = 0x0F
CONNECTION_PARAM_RSP = 0x10
REJECT_IND_EXT = 0x11
PING_REQ = 0x12
PING_RSP = 0x13
LENGTH_REQ = 0x14
LENGTH_RSP = 0x15

class BleConnection:
    """BLE connection implementation
    """

    def __init__(self, l2cap_instance, conn_handle, local_peer_addr, remote_peer_addr):
        self.__l2cap = l2cap_instance
        self.__conn_handle = conn_handle
        self.__remote_peer = remote_peer_addr
        self.__local_peer = local_peer_addr
        self.__lock = Lock()

    @property
    def remote_peer(self):
        """Remote peer address
        """
        return self.__remote_peer

    @property
    def local_peer(self):
        """Local peer address
        """
        return self.__local_peer

    @property
    def conn_handle(self) -> int:
        """Connection handle
        """
        return self.__conn_handle

    @property
    def l2cap(self):
        """Associated L2CAP instance
        """
        return self.__l2cap

    @property
    def gatt(self):
        """Reference to the associated GATT layer
        """
        return self.__l2cap.get_layer("gatt")

    @property
    def smp(self):
        """Security Manager Protocol instance
        """
        return self.__l2cap.get_layer("smp")

    @property
    def phy(self):
        """PHY layer
        """
        return self.__l2cap.get_layer("phy")

    @property
    def ll(self):
        """Link layer
        """
        return self.__l2cap.get_layer("ll")
    
    @property
    def att(self):
        """ATT layer
        """
        return self.__l2cap.get_layer("att")

    @property
    def remote_version(self):
        """Query remote peer BLE version
        """
        return self.ll.state.get_version_remote(self.__conn_handle)

    def lock(self):
        """Lock connection
        """
        self.__lock.acquire()

    def unlock(self):
        """Unlock connection
        """
        self.__lock.release()

    def on_disconnect(self):
        """Connection has been closed.
        """

    def send_version(self):
        """Send LL_VERSION_IND PDU.
        """
        if not self.ll.state.get_connection(self.__conn_handle)['version_sent']:
            # Mark version as sent
            self.ll.state.get_connection(self.__conn_handle)['version_sent'] = True

            # Send LL_VERSION_IND PDU
            self.ll.send_ctrl_pdu(
                self.__conn_handle,
                LL_VERSION_IND(
                    version=self.phy.bt_version.value,
                    company=self.phy.manufacturer_id,
                    subversion=self.phy.bt_sub_version
                )
            )

class LinkLayerState(LayerState):
    """BLE Link layer state
    """

    def __init__(self):
        super().__init__()
        self.connections = {}

    def get_connection(self, conn_handle) -> BleConnection:
        """Retrieve a BleConnection object from a connection handle.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: The BleConnection object associated with a specific connection
                 handle, if any
        :rtype: BleConnection
        :raises: IndexError
        """
        if conn_handle in self.connections:
            return self.connections[conn_handle]
        raise IndexError

    def register_connection(self, conn_handle, l2cap_instance, local_peer_addr: BDAddress,
                            remote_peer_addr: BDAddress):
        """Register a connection into this link-layer state.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param l2cap_instance: L2CAP instance
        :type l2cap_instance: Layer
        :param local_peer_addr: Local peer address
        :type local_peer_addr: BDAddress
        :param remote_peer_addr: Remote peer address
        :type remote_peer_addr: BDAddress
        """
        self.connections[conn_handle] = {
            'l2cap': l2cap_instance,
            'local_peer_addr': local_peer_addr.value,
            'local_peer_addr_type': local_peer_addr.type,
            'remote_peer_addr': remote_peer_addr.value,
            'remote_peer_addr_type': remote_peer_addr.type,
            'version_sent': False,  # version exchanged
            'version_remote': None,
            'encryption_key':None,
            'authenticated':False,
            'encrypted':False,
            'skd':None,
            'iv':None,
            'rand':None,
            'ediv':None,
            'nb_pdu_recvd': 0       # number of packets received
        }

    def unregister_connection(self, conn_handle: int):
        """Unregister a specific connection from this state.

        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        if conn_handle in self.connections:
            del self.connections[conn_handle]

    def get_connection_l2cap(self, conn_handle: int) -> Layer:
        """Retrieve a connection L2CAP instance

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: L2CAP layer if any, None otherwise
        :rtype: Layer
        """
        if conn_handle in self.connections:
            return self.connections[conn_handle]['l2cap']
        return None

    def get_connection_handle(self, l2cap_instance: Layer) -> int:
        """Get connection handle from L2CAP instance

        :param l2cap_instance: L2CAP layer instance
        :type l2cap_instance: Layer
        :return: Associated connection handle if found, else None
        :rtype: None
        """
        for conn_handle, conn in self.connections.items():
            if conn['l2cap'] == l2cap_instance:
                return conn_handle
        return None

    def register_encryption_key(self, conn_handle: int, key: bytes):
        """Register an encryption key for a connection.
        """
        if conn_handle in self.connections:
            self.connections[conn_handle]['encryption_key'] = key

    def is_authenticated(self, conn_handle: int) -> bool:
        """Check if connection is authenticated.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: `True` if connection is authenticated, `False` otherwise
        :rtype: bool
        """
        if conn_handle in self.connections:
            return self.connections[conn_handle]['authenticated']
        # Not found, return False
        return False

    def is_encrypted(self, conn_handle: int) -> bool:
        """Check if connection is encrypted

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: `True` if connection is encrypted, `False` otherwise
        :rtype: bool
        """
        if conn_handle in self.connections:
            return self.connections[conn_handle]['encrypted']
        return False

    def mark_as_authenticated(self, conn_handle: int):
        """Mark connection as authenticated

        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        if conn_handle in self.connections:
            self.connections[conn_handle]['authenticated'] = True

    def mark_as_encrypted(self, conn_handle: int):
        """Mark connection as encrypted

        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        if conn_handle in self.connections:
            self.connections[conn_handle]['encrypted'] = True

    def get_encryption_key(self, conn_handle: int) -> bytes:
        """Retrieve encryption key for a given connection

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: Encryption key if found, `None` otherwise
        :rtype: bytes
        """
        if conn_handle in self.connections:
            return self.connections[conn_handle]['encryption_key']
        return None

    def register_skd_and_iv(self, conn_handle: int, skd: int, iv: int):
        """Register SKD and IV for a given connection

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param skd: SKD for this connection
        :type skd: int
        :param iv: IV for this connection
        :type iv: int
        """
        if conn_handle in self.connections:
            self.connections[conn_handle]['skd'] = skd
            self.connections[conn_handle]['iv'] = iv

    def get_skd_and_iv(self, conn_handle: int) -> Tuple[int, int]:
        """Retrieve SKD and IV for a given connection

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: SKD and IV if found, tuple of None values otherwise
        :rtype: tuple
        """
        if conn_handle in self.connections:
            skd = self.connections[conn_handle]['skd']
            iv = self.connections[conn_handle]['iv']
            return (skd, iv)
        return (None, None)

    def register_rand_and_ediv(self, conn_handle: int, rand: int, ediv: int):
        """Register RAND and EDIV for a given connection

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param rand: RAND value
        :type rand: int
        :param ediv: EDIV value
        :type ediv: int
        """
        if conn_handle in self.connections:
            self.connections[conn_handle]['rand'] = rand
            self.connections[conn_handle]['ediv'] = ediv

    def get_rand_and_ediv(self, conn_handle: int) -> Tuple[int, int]:
        """Retrieve RAND and EDIV for a given connection

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: RAND and EDIV values for the given connection
        :rtype: tuple
        """
        if conn_handle in self.connections:
            rand = self.connections[conn_handle]['rand']
            ediv = self.connections[conn_handle]['ediv']
            return (rand, ediv)
        return (None, None)

    def mark_version_sent(self, conn_handle: int):
        """Mark version sent for this connection

        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        if conn_handle in self.connections:
            self.connections[conn_handle]['version_sent'] = True

    def is_version_sent(self, conn_handle: int) -> bool:
        """Check if version PDU has already been sent

        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        if conn_handle in self.connections:
            return self.connections[conn_handle]['version_sent']
        return False

    def set_version_remote(self, conn_handle: int, version: LL_VERSION_IND):
        """Set version for remote device

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param version: Version information
        :type version: LL_VERSION_IND
        """
        if conn_handle in self.connections:
            self.connections[conn_handle]['version_remote'] = version

    def get_version_remote(self, conn_handle: int) -> LL_VERSION_IND:
        """Retrieve version information for a given connection

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: Remote peer version PDU if found, `None` otherwise 
        """
        if conn_handle in self.connections:
            return self.connections[conn_handle]['version_remote']
        return None

@alias('ll')
@state(LinkLayerState)
class LinkLayer(Layer):
    """Bluetooth Low Energy link-layer implementation.
    """

    def __init__(self, parent=None, layer_name=None, options=None):
        super().__init__(parent=parent, layer_name=layer_name, options=options)
        self.__llcm = None

    def configure(self, options=None):
        # Control PDU dispatch
        self.__handlers = {
            CONNECTION_UPDATE_REQ: self.on_connection_update_req,
            CHANNEL_MAP_REQ: self.on_channel_map_req,
            TERMINATE_IND: self.on_terminate_ind,
            ENC_REQ: self.on_enc_req,
            ENC_RSP: self.on_enc_rsp,
            START_ENC_REQ: self.on_start_enc_req,
            START_ENC_RSP: self.on_start_enc_rsp,
            UNKNOWN_RSP: self.on_unknown_rsp,
            FEATURE_REQ: self.on_feature_req,
            FEATURE_RSP: self.on_feature_rsp,
            PAUSE_ENC_REQ: self.on_pause_enc_req,
            PAUSE_ENC_RSP: self.on_pause_enc_rsp,
            VERSION_IND: self.on_version_ind,
            REJECT_IND: self.on_reject_ind,
            SLAVE_FEATURE_REQ: self.on_slave_feature_req,
            CONNECTION_PARAM_REQ: self.on_connection_param_req,
            CONNECTION_PARAM_RSP: self.on_connection_param_rsp,
            REJECT_IND_EXT: self.on_reject_ind_ext,
            PING_REQ: self.on_ping_req,
            PING_RSP: self.on_ping_rsp,
            LENGTH_REQ: self.on_length_req,
            LENGTH_RSP: self.on_length_rsp
        }

    def on_connect(self, conn_handle, local_peer_addr, remote_peer_addr):
        """Handles BLE connection
        """
        if conn_handle not in self.state.connections:
            logger.info("[llm] registers new connection %d with %s", conn_handle,
                        remote_peer_addr)

            # Instantiate a L2CAP layer (contextual) to handle the connection
            conn_l2cap = self.instantiate(L2CAPLayer)
            conn_l2cap.set_conn_handle(conn_handle)

            # Update state with new connection
            self.state.register_connection(conn_handle, conn_l2cap.name, local_peer_addr,
                                           remote_peer_addr)

            # Return connection object
            return BleConnection(
                conn_l2cap,
                conn_handle,
                local_peer_addr,
                remote_peer_addr
            )
        # Connection already exists
        logger.error('[!] Connection already exists')

        # Return connection object
        return BleConnection(
            self,
            conn_handle,
            local_peer_addr,
            remote_peer_addr
        )

    def on_disconnect(self, conn_handle: int):
        """Handle disconnection event

        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        # Free the previously instantiated L2CAP layer
        conn_layer = self.state.get_connection_l2cap(conn_handle)
        if conn_layer is not None:
            # Mark GATT layer as disconnected
            self.get_layer(conn_layer).get_layer("gatt").state.terminated = True
            self.destroy(self.get_layer(conn_layer))

        # Remove connection from our registered connections
        self.state.unregister_connection(conn_handle)

    @source('phy', 'data')
    def on_data_pdu_recv(self, pdu: Packet, conn_handle: int = None):
        """Handle data PDU sent by our PHY layer

        :param pdu: Incoming PDU to process
        :type pdu: Packet
        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        # Count PDU
        if conn_handle in self.state.connections:
            conn_metadata = self.state.get_connection(conn_handle)
            conn_metadata['nb_pdu_recvd'] += 1

        # We received a data PDU
        self.on_data_pdu(pdu, conn_handle)

    @source('phy', 'control')
    def on_ctrl_pdu_recv(self, pdu: Packet, tag: str = None, conn_handle: int = None):
        """Handle control PDU received by our PHY layer

        :param pdu: Received control PDU
        :type pdu: Packet
        :param tag: Optional tag
        :type tag: str, optional
        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        # Count PDU
        if conn_handle in self.state.connections:
            conn_metadata = self.state.get_connection(conn_handle)
            conn_metadata['nb_pdu_recvd'] += 1

        # We received a control PDU
        self.on_ctrl_pdu(pdu, conn_handle)

    def on_ctrl_pdu(self, pdu: Packet, conn_handle: int):
        """Process a specific control PDU by calling the associated
        control PDU type handler.

        :param pdu: Control PDU
        :type pdu: Packet
        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        if conn_handle in self.state.connections:
            ctrl = pdu.getlayer(BTLE_CTRL)
            if ctrl.opcode in self.__handlers:
                self.__handlers[int(ctrl.opcode)](conn_handle, ctrl.getlayer(1))
        else:
            logger.error('[!] Unknown connection handle: %d', conn_handle)


    def on_data_pdu(self, pdu: Packet, conn_handle: int):
        """Forward data PDU to the upper layer (L2CAP) instance of the
        connection identified by its connection handle.

        :param pdu: Incoming data PDU
        :type pdu: Packet
        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        # We look for the corresponding L2CAP layer instance
        l2cap_layer = self.state.get_connection_l2cap(conn_handle)
        if l2cap_layer is not None:
            self.send(l2cap_layer, bytes(pdu.payload), fragment=pdu.LLID == 0x1)

    @instance('l2cap')
    def on_l2cap_send_data(self, l2cap_inst: Layer, data: Packet, fragment=False, encrypt=None):
        '''Handle L2CAP packets coming from our L2CAP layer and encapsulate them into a
        BTLE_DATA packet (data PDU).

        :param l2cap_inst: Connection L2CAP instance
        :type l2cap_inst: Layer
        :param data: L2CAP packet to forward to PHY
        :type data: Packet
        :param fragment: If set to `True`, will set the fragment flag in the data PDU.
        :type fragment: bool
        :param encrypt: If set to `True`, enable encryption for this data PDU
        :type encrypt: bool
        '''
        # Retrieve connection handle corresponding to the instance
        conn_handle = self.state.get_connection_handle(l2cap_inst)
        if conn_handle is not None:
            logger.debug("sending l2cap data PDU for conn_handle %d (%d bytes)", conn_handle,len(data))
            llid = 0x01 if fragment else 0x02
            self.send(
                'phy',
                BTLE_DATA(
                    LLID=llid,
                    len=len(data)
                )/data,
                tag='data',
                conn_handle=conn_handle,
                encrypt=encrypt
            )
        else:
            logger.error("no connection handle found for L2CAP instance %s", instance)

    @instance('l2cap', tag='ATT_MTU')
    def on_l2cap_mtu_changed(self, l2cap_inst: Layer, mtu: int):
        """Handle MTU value change notification from L2CAP layer.

        :param l2cap_inst: Connection L2CAP instance
        :type l2cap_inst: Layer
        :param mtu: Updated MTU value
        :param mtu: int
        """
        # Retrieve connection handle corresponding to the instance
        conn_handle = self.state.get_connection_handle(l2cap_inst)
        if conn_handle is not None:
            logger.debug("sending updated ATT MTU (%d) for conn_handle %d", mtu, conn_handle)
            self.send(
                'phy',
                mtu,
                tag='ATT_MTU',
                conn_handle=conn_handle
            )

    def send_ctrl_pdu(self, conn_handle: int, pdu: Packet, encrypt: bool = None):
        """Send a control PDU to the underlying PHY layer.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param pdu: control PDU to send
        :type pdu: Packet
        :param encrypt: If set to `True`, control PDU will be sent encrypted
        :type encrypt: bool
        """
        self.send('phy', BTLE_DATA()/BTLE_CTRL()/pdu, tag='control',
                  conn_handle=conn_handle, encrypt=encrypt)


    ### Link-layer control PDU callbacks

    def on_unsupported_opcode(self, conn_handle: int, opcode: int):
        """Handle unsupported control PDU opcodes.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param opcode: control PDU opcode
        :type opcode: int
        """
        self.send_ctrl_pdu(
            conn_handle,
            LL_UNKNOWN_RSP(code=opcode)
        )

    def on_connection_update_req(self, conn_handle: int, conn_update: LL_CONNECTION_UPDATE_IND):
        """Connection update is not supported yet

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param conn_update: Connection update PDU
        :type conn_update: LL_CONNECTION_UPDATE_IND
        """
        self.on_unsupported_opcode(conn_handle, CONNECTION_UPDATE_REQ)

    def on_channel_map_req(self, conn_handle: int, channel_map: LL_CHANNEL_MAP_IND):
        """Channel map update is not supported yet

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param channel_map: channel map PDU
        :type channel_map: LL_CHANNEL_MAP_IND
        """
        self.on_unsupported_opcode(conn_handle, CHANNEL_MAP_REQ)

    def on_terminate_ind(self, conn_handle: int, terminate: LL_TERMINATE_IND):
        """Terminate this connection

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param terminate: Terminate PDU
        :type terminate: LL_TERMINATE_IND
        """
        # Connection has been terminated
        conn = self.state.get_connection(conn_handle)
        if conn is not None:
            self.on_disconnect(conn_handle)

    def start_encryption(self, conn_handle: int, rand: int, ediv: int):
        """
        Initiate encryption procedure.
        """
        # Retrieve connection handle corresponding to the instance

        encryption_key = None
        if conn_handle is not None:
            encryption_key = self.state.get_encryption_key(conn_handle)

        # Allowed if we have already negociated an STK
        if encryption_key is not None and conn_handle is not None:

            # Generate our SKD and IV
            skd = randint(0, 0x10000000000000000)
            iv = randint(0, 0x100000000)
            self.state.register_skd_and_iv(conn_handle, skd, iv)

            logger.info('[llm] Initiate connection LinkLayerCryptoManager')

            # Save master rand/iv
            self.state.register_rand_and_ediv(conn_handle, rand, ediv)

            # Send back our parameters
            self.send_ctrl_pdu(
                conn_handle,
                LL_ENC_REQ(
                    rand = rand,
                    ediv = ediv,
                    skdm = skd,
                    ivm = iv
                )
            )

        else:
            self.send_ctrl_pdu(
                conn_handle,
                LL_REJECT_IND(
                    code=0x1A # Unsupported Remote Feature
                )
            )

    def on_enc_rsp(self, conn_handle, enc_rsp: LL_ENC_RSP):
        """Encryption response handler

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param enc_rsp: Encryption response PDU
        :type enc_rsp: LL_ENC_RSP
        """
        # Retrieve connection handle corresponding to the instance

        encryption_key = None
        if conn_handle is not None:
            encryption_key = self.state.get_encryption_key(conn_handle)


        # Allowed if we have already negociated an STK
        if encryption_key is not None and conn_handle is not None:

            skdm, ivm = self.state.get_skd_and_iv(conn_handle)
            rand, ediv = self.state.get_rand_and_ediv(conn_handle)

            logger.info(
                "[llm] Received LL_ENC_RSP: skds=%s ivs=%s",
                pack('<Q', enc_rsp.skds).hex(),
                pack('<I', enc_rsp.ivs).hex(),
            )

            logger.info('[llm] Initiate connection LinkLayerCryptoManager')

            # Initiate LLCM
            self.__llcm = LinkLayerCryptoManager(
                encryption_key,
                skdm,
                ivm,
                enc_rsp.skds,
                enc_rsp.ivs
            )

            # Compute session key
            master_skd = pack(">Q", skdm)
            master_iv = pack("<L", ivm)
            slave_skd = pack(">Q", enc_rsp.skds)
            slave_iv = pack("<L", enc_rsp.ivs)

            # Generate session key diversifier
            skd = slave_skd + master_skd

            # Generate initialization vector
            iv = master_iv + slave_iv

            # Generate session key
            session_key = e(encryption_key, skd)

            logger.info("[llm] master  skd: %s", master_skd.hex())
            logger.info("[llm] master   iv: %s", master_iv.hex())
            logger.info("[llm] slave   skd: %s", slave_skd.hex())
            logger.info("[llm] slave    iv: %s", slave_iv.hex())
            logger.info("[llm] Session  TK: %s", encryption_key.hex())
            logger.info("[llm] Session  iv: %s", iv.hex())
            logger.info("[llm] Exp. Ses iv: %s", self.__llcm.iv.hex())
            logger.info("[llm] Session key: %s", session_key.hex())


            # Notify encryption enabled
            if not self.get_layer('phy').set_encryption(
                conn_handle=conn_handle,
                enabled=True,
                ll_key=session_key,
                ll_iv=iv,
                key=encryption_key,
                rand=rand,
                ediv=ediv
            ):
                logger.info('[llm] Cannot enable encryption')
            else:
                logger.info('[llm] Encryption enabled in hardware')

        else:
            self.send_ctrl_pdu(
                conn_handle,
                LL_REJECT_IND(
                    code=0x1A # Unsupported Remote Feature
                )
            )


    def on_enc_req(self, conn_handle: int, enc_req: LL_ENC_REQ):
        """Encryption request handler

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param enc_req: Encryption request PDU
        :type enc_req: LL_ENC_REQ
        """
        # Retrieve connection handle corresponding to the instance

        encryption_key = None
        if conn_handle is not None:
            encryption_key = self.state.get_encryption_key(conn_handle)

        # Allowed if we have already negociated an STK
        if encryption_key is not None and conn_handle is not None:

            # Generate our SKD and IV
            skd = randint(0, 0x10000000000000000)
            iv = randint(0, 0x100000000)
            self.state.register_skd_and_iv(conn_handle, skd, iv)

            logger.info(
                "[llm] Received LL_ENC_REQ: rand=%s ediv=%s skd=%s iv=%s",
                pack('<Q', enc_req.rand).hex(),
                pack('<H', enc_req.ediv).hex(),
                pack('<Q', enc_req.skdm).hex(),
                pack('<I', enc_req.ivm).hex(),
            )

            logger.info("[llm] Initiate connection LinkLayerCryptoManager")

            # Save master rand/iv
            self.state.register_rand_and_ediv(conn_handle, enc_req.rand, enc_req.ediv)

            # Initiate LLCM
            self.__llcm = LinkLayerCryptoManager(
                encryption_key,
                enc_req.skdm,
                enc_req.ivm,
                skd,
                iv
            )

            # Compute session key
            master_skd = pack(">Q", enc_req.skdm)
            master_iv = pack("<L", enc_req.ivm)
            slave_skd = pack(">Q", skd)
            slave_iv = pack("<L", iv)

            # Generate session key diversifier
            skd = slave_skd + master_skd

            # Generate initialization vector
            iv = master_iv + slave_iv

            # Generate session key
            session_key = e(encryption_key, skd)

            logger.info("[llm] master  skd: %s", master_skd.hex())
            logger.info("[llm] master   iv: %s", master_iv.hex())
            logger.info("[llm] slave   skd: %s", slave_skd.hex())
            logger.info("[llm] slave    iv: %s", slave_iv.hex())
            logger.info("[llm] Session  TK: %s", encryption_key.hex())
            logger.info("[llm] Session  iv: %s", iv.hex())
            logger.info("[llm] Exp. Ses iv: %s", self.__llcm.iv.hex())
            logger.info("[llm] Session key: %s", session_key.hex())
            skdm, ivm = self.state.get_skd_and_iv(conn_handle)
            logger.info(
                "[llm] Send LL_ENC_RSP: skd=%s iv=%s",
                pack('<Q', skdm).hex(),
                pack('<I', ivm).hex(),
            )

            # Send back our parameters
            self.send_ctrl_pdu(
                conn_handle,
                LL_ENC_RSP(
                    skds = skdm,
                    ivs = ivm
                )
            )

            # Notify encryption enabled
            if not self.get_layer('phy').set_encryption(
                conn_handle=conn_handle,
                enabled=True,
                ll_key=session_key,
                ll_iv=iv,
                key=encryption_key,
                rand=enc_req.rand,
                ediv=enc_req.ediv
            ):
                logger.info('[llm] Cannot enable encryption')
            else:
                logger.info('[llm] Encryption enabled in hardware')

            # Start encryption (STK as LTK)
            self.send_ctrl_pdu(
                conn_handle,
                LL_START_ENC_REQ(),
                encrypt=False
            )

        else:
            self.send_ctrl_pdu(
                conn_handle,
                LL_REJECT_IND(
                    code=0x1A # Unsupported Remote Feature
                )
            )

    def on_start_enc_req(self, conn_handle: int, start_enc_req: LL_START_ENC_REQ):
        """Encryption start request handler.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param start_enc_req: Start encryption request PDU
        :type start_enc_req: LL_START_ENC_REQ
        """

        # Start encryption (STK as LTK)
        self.send_ctrl_pdu(
            conn_handle,
            LL_START_ENC_RSP()
        )

    def on_start_enc_rsp(self, conn_handle: int, start_enc_rsp: LL_START_ENC_RSP):
        """Encryption start response handler

        Normally, we get this packet when a link has successfully
        been encrypted (with STK or LTK). So we need to notify the
        SMP that encryption has been acknowledged by the remote peer.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param start_enc_rsp: Start encryption response PDU
        :type start_enc_rsp: LL_START_ENC_RSP
        """
        # Check if we are the encryption initiator,
        # if yes then we need to answer to this encrypted LL_START_ENC_RSP
        # with another encrypted LL_START_ENC_RSP
        l2cap_instance = self.state.get_connection_l2cap(conn_handle)
        if not self.get_layer(l2cap_instance).get_layer('smp').is_initiator():
            self.send_ctrl_pdu(
                conn_handle,
                LL_START_ENC_RSP()
            )

        #print("Marked as encrypted")
        self.state.mark_as_encrypted(conn_handle)

        # Notify SMP channel is now encrypted
        self.get_layer(l2cap_instance).get_layer('smp').on_channel_encrypted()

    def on_unknown_rsp(self, conn_handle: int, unk_rsp: LL_UNKNOWN_RSP):
        """handle unknown response PDU (not expected).

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param unk_rsp: Unknown response PDU
        :type unk_rsp: LL_UNKNOWN_RSP
        """

    def on_feature_req(self, conn_handle: int, feature_req: LL_FEATURE_REQ):
        """Handle feature request

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param feature_req: Feature request PDU
        :type feature_req: LL_FEATURE_REQ
        """
        #self.on_unsupported_opcode(FEATURE_REQ)
        # Reply with our basic feature set
        self.send_ctrl_pdu(
            conn_handle,
            LL_FEATURE_RSP(feature_set=[
                'le_encryption',
                'le_ping'
            ])
        )

    def on_feature_rsp(self, conn_handle: int, feature_rsp: LL_FEATURE_RSP):
        """Features not supported yet

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param feature_rsp: Feature response PDU
        :type feature_rsp: LL_FEATURE_RSP
        """
        self.on_unsupported_opcode(conn_handle, FEATURE_RSP)

    def on_pause_enc_req(self, conn_handle: int, pause_enc_req: LL_PAUSE_ENC_RSP):
        """Encryption not supported yet.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param pause_enc_req: Pause encryption request PDU
        :type pause_enc_req: LL_PAUSE_ENC_RSP
        """
        self.on_unsupported_opcode(conn_handle, PAUSE_ENC_REQ)

    def on_pause_enc_rsp(self, conn_handle: int, pause_enc_rsp: LL_PAUSE_ENC_RSP):
        """Encryption not supported yet.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param pause_enc_rsp: Pause encryption response PDU
        :type pause_enc_rsp: LL_PAUSE_ENC_RSP
        """
        self.on_unsupported_opcode(conn_handle, PAUSE_ENC_RSP)

    def on_version_ind(self, conn_handle: int, version: LL_VERSION_IND):
        """Send back our version info

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param version: Remote peer version PDU
        :type version: LL_VERSION_IND
        """
        logger.debug('received a VERSION_IND PDU')
        if not self.state.is_version_sent(conn_handle):
            logger.debug('sending back our VERSION_IND PDU')

            # send control PDU
            self.send_ctrl_pdu(
                conn_handle,
                LL_VERSION_IND(
                    version=self.get_layer('phy').bt_version.value,
                    company=self.get_layer('phy').manufacturer_id,
                    subversion=self.get_layer('phy').bt_sub_version
                )
            )
        else:
            logger.debug('VERSION_IND PDU already sent, skip.')
        self.state.set_version_remote(conn_handle, version)
        self.state.mark_version_sent(conn_handle)

    def on_reject_ind(self, conn_handle: int, reject: int):
        """Handle reject PDU

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param reject: rejection reason
        :type reject: int
        """

    def on_slave_feature_req(self, conn_handle: int, feature_req: LL_SLAVE_FEATURE_REQ):
        """Handle slave feature request, return unsupported PDU for now.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param feature_req: Slave feature request packet
        :type feature_req: Packet
        """
        self.on_unsupported_opcode(conn_handle, SLAVE_FEATURE_REQ)

    def on_connection_param_req(self, conn_handle: int, conn_param_req: LL_CONNECTION_PARAM_REQ):
        """Handle connection parameter request

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param conn_param_req: Connection parameter request packet
        :type conn_param_req: LL_CONNECTION_PARAM_REQ
        """
        self.on_unsupported_opcode(conn_handle, CONNECTION_PARAM_REQ)

    def on_connection_param_rsp(self, conn_handle: int, conn_param_rsp: LL_CONNECTION_PARAM_RSP):
        """Handle connection parameter response

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param conn_param_rsp: Connection parameter response
        :type conn_param_rsp: LL_CONNECTION_PARAM_RSP
        """

    def on_reject_ind_ext(self, conn_handle: int, reject_ext: LL_REJECT_EXT_IND):
        """Handle extended rejection PDU

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param reject_ext: Extended rejection PDU
        :type reject_ext: LL_REJECT_EXT_IND
        """

    def on_ping_req(self, conn_handle: int, ping_req: LL_PING_REQ):
        """Handle ping request (not supported for now)

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param ping_req: Ping request PDU
        :type ping_req: LL_PING_REQ
        """
        self.on_unsupported_opcode(conn_handle, PING_REQ)

    def on_ping_rsp(self, conn_handle: int, ping_rsp: LL_PING_RSP):
        """Handle ping response (unsupported for now).

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param ping_rsp: Ping response PDU
        :type ping_rsp: LL_PING_RSP
        """

    def on_length_req(self, conn_handle: int, length_req: LL_LENGTH_REQ):
        """Received a length request PDU (unsupported for now)

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param length_req: Length request PDU
        :type length_req: LL_LENGTH_REQ
        """
        self.on_unsupported_opcode(conn_handle, LENGTH_REQ)

    def on_length_rsp(self, conn_handle: int, length_rsp: LL_LENGTH_RSP):
        """Handle length response

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param length_rsp: Length response
        :type length_rsp: LL_LENGTH_RSP
        """

LinkLayer.add(L2CAPLayer)
