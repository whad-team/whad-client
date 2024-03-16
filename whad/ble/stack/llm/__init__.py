"""
Bluetooth LE Stack Link-layer Manager
"""
from binascii import hexlify
from struct import pack
from random import randint

from threading import Lock

from scapy.layers.bluetooth4LE import *

from whad.common.stack import Layer, alias, source, state, LayerState, instance
from whad.ble.stack.l2cap import L2CAPLayer
from whad.ble.crypto import LinkLayerCryptoManager, generate_random_value, e

import logging
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


''' Kept BleConnection because of pairing stuff in it.

class BleConnection(object):

    def __init__(self, llm, conn_handle, local_peer_addr, remote_peer_addr):
        self.__llm = llm
        self.__conn_handle = conn_handle
        self.__local_peer = local_peer_addr
        self.__remote_peer = remote_peer_addr
        self.__l2cap = BleL2CAP(self)
        self.__encrypted = False
        self.__llcm = None
        self.__version_sent = False
        self.__version_remote = None
        self.__lock = Lock()

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

    @property
    def remote_peer(self):
        return self.__remote_peer

    @property
    def local_peer(self):
        return self.__local_peer

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
        # Notify GATT layer that the connection has been terminated.
        if self.__l2cap.gatt is not None:
            self.__l2cap.gatt.on_terminated()
            #self.__llm.on_disconnected()

    def on_ctrl_pdu(self, control):
        """Handle Control PDU at connection-level"""
        ctrl = control.getlayer(BTLE_CTRL)
        if ctrl.opcode in self.__handlers:
            self.__handlers[int(ctrl.opcode)](ctrl.getlayer(1))


    def on_l2cap_data(self, data, fragment=False):
        """Forward L2CAP data to L2CAP layer"""
        self.__l2cap.on_data_received(data, fragment)

    def send_l2cap_data(self, data, fragment=False, encrypt=None):
        """Sends data back
        """
        self.__llm.send_data(self.__conn_handle, data, fragment, encrypt=encrypt)

    def send_control(self, pdu, encrypt=None):
        """Sends back a control PDU
        """
        self.__llm.send_control(self.__conn_handle, pdu, encrypt=encrypt)

    @property
    def gatt_class(self):
        return self.__llm.gatt_class

    @property
    def gatt(self):
        return self.__l2cap.att.gatt

    @property
    def conn_handle(self):
        return self.__conn_handle

    @property
    def remote_version(self):
        return self.__version_remote

    def set_stk(self, stk):
        self.__encrypted = True
        self.__stk = stk

    def set_ltk(self, ltk):
        self.__ltk = ltk

    ### Link-layer control PDU callbacks

    def on_unsupported_opcode(self, opcode):
        self.send_control(
            BTLE_CTRL() / LL_UNKNOWN_RSP(code=opcode)
        )

    def on_connection_update_req(self, conn_update):
        """Connection update is not supported yet
        """
        self.on_unsupported_opcode(CONNECTION_UPDATE_REQ)

    def on_channel_map_req(self, channel_map):
        """Channel map update is not supported yet
        """
        self.on_unsupported_opcode(CHANNEL_MAP_REQ)

    def on_terminate_ind(self, terminate):
        """Terminate this connection
        """
        # Notify Link-layer manager that our connection has been terminated
        self.__llm.on_disconnect(self.__conn_handle)

    def on_enc_req(self, enc_req):
        """Encryption request handler
        """
        # Allowed if we have already negociated an STK
        if self.__stk is not None:

            # Generate our SKD and IV
            self.__skd = randint(0, 0x10000000000000000)
            self.__iv = randint(0, 0x100000000)

            logger.info('[llm] Received LL_ENC_REQ: rand=%s ediv=%s skd=%s iv=%s' % (
                hexlify(pack('<Q', enc_req.rand)),
                hexlify(pack('<H', enc_req.ediv)),
                hexlify(pack('<Q', enc_req.skdm)),
                hexlify(pack('<I', enc_req.ivm)),
            ))

            logger.info('[llm] Initiate connection LinkLayerCryptoManager')

            # Save master rand/iv
            self.__randm = enc_req.rand
            self.__ediv = enc_req.ediv

            # Initiate LLCM
            self.__llcm = LinkLayerCryptoManager(
                self.__stk,
                enc_req.skdm,
                enc_req.ivm,
                self.__skd,
                self.__iv
            )

            # Compute session key
            master_skd = pack(">Q", enc_req.skdm)
            master_iv = pack("<L", enc_req.ivm)
            slave_skd = pack(">Q", self.__skd)
            slave_iv = pack("<L", self.__iv)

            # Generate session key diversifier
            skd = slave_skd + master_skd

            # Generate initialization vector
            iv = master_iv + slave_iv

            # Generate session key
            session_key = e(self.__stk, skd)

            logger.info('[llm] master  skd: %s' % hexlify(master_skd))
            logger.info('[llm] master   iv: %s' % hexlify(master_iv))
            logger.info('[llm] slave   skd: %s' % hexlify(slave_skd))
            logger.info('[llm] slave    iv: %s' % hexlify(slave_iv))
            logger.info('[llm] Session  TK: %s' % hexlify(self.__stk))
            logger.info('[llm] Session  iv: %s' % hexlify(iv))
            logger.info('[llm] Exp. Ses iv: %s' % hexlify(self.__llcm.iv))
            logger.info('[llm] Session key: %s' % hexlify(session_key))

            logger.info('[llm] Send LL_ENC_RSP: skd=%s iv=%s' % (
                hexlify(pack('<Q', self.__skd)),
                hexlify(pack('<I', self.__iv))
            ))

            # Send back our parameters
            self.send_control(
                BTLE_CTRL() / LL_ENC_RSP(
                    skds = self.__skd,
                    ivs = self.__iv
                )
            )

            # Notify encryption enabled
            if not self.__llm.set_encryption(
                self.conn_handle,
                enabled = True,
                key=session_key,
                iv=iv
            ):
                logger.info('[llm] Cannot enable encryption')
            else:
                logger.info('[llm] Encryption enabled in hardware')

            # Start encryption (STK as LTK)
            self.send_control(
                BTLE_CTRL() / LL_START_ENC_REQ(),
                encrypt=False
            )

        else:
            self.send_control(


                BTLE_CTRL() / LL_REJECT_IND(
                    code=0x1A # Unsupported Remote Feature
                )
            )

    def on_enc_rsp(self, enc_rsp):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(ENC_RSP)

    def on_start_enc_req(self, start_enc_req):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(START_ENC_REQ)

    def on_start_enc_rsp(self, start_enc_rsp):
        """Encryption start response handler

        Normally, we get this packet when a link has successfully
        been encrypted (with STK or LTK). So we need to notify the
        SMP that encryption has been acknowledged by the remote peer.


        """
        # Check if we are the encryption initiator,
        # if yes then we need to answer to this encrypted LL_START_ENC_RSP
        # with another encrypted LL_START_ENC_RSP
        if not self.__l2cap.smp.is_initiator():
            self.send_control(
                BTLE_CTRL() / LL_START_ENC_RSP()
            )

        # Notify SMP channel is now encrypted
        self.__l2cap.smp.on_channel_encrypted()

    def on_unknown_rsp(self, unk_rsp):
        pass

    def on_feature_req(self, feature_req):
        """Features not supported yet
        """
        #self.on_unsupported_opcode(FEATURE_REQ)
        # Reply with our basic feature set
        self.send_control(
            BTLE_CTRL() / LL_FEATURE_RSP(feature_set=[
                'le_encryption',
                'le_ping'
            ])
        )

    def on_feature_rsp(self, feature_rsp):
        """Features not supported yet
        """
        self.on_unsupported_opcode(FEATURE_RSP)

    def on_pause_enc_req(self, pause_enc_req):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(PAUSE_ENC_REQ)

    def on_pause_enc_rsp(self, pause_enc_rsp):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(PAUSE_ENC_RSP)

    def on_version_ind(self, version):
        """Send back our version info
        """
        if not self.__version_sent:
            self.send_control(
                BTLE_CTRL() / LL_VERSION_IND(
                    version=self.__llm.stack.bt_version,
                    company=self.__llm.stack.manufacturer_id,
                    subversion=self.__llm.stack.bt_sub_version
                )
            )
        self.__version_remote = version

    def on_reject_ind(self, reject):
        pass

    def on_slave_feature_req(self, feature_req):
        self.on_unsupported_opcode(FEATURE_REQ)

    def on_connection_param_req(self, conn_param_req):
        self.on_unsupported_opcode(CONNECTION_PARAM_REQ)

    def on_connection_param_rsp(self, conn_param_rsp):
        pass

    def on_reject_ind_ext(self, reject_ext):
        pass

    def on_ping_req(self, ping_req):
        pass

    def on_ping_rsp(self, ping_rsp):
        pass

    def on_length_req(self, length_req):
        """Received a length request PDU
        """
        pass

    def on_length_rsp(self, length_rsp):
        pass

    ##################################
    # LLM control procedures
    ##################################

    def send_version(self):
        """Send LL_VERSION_IND PDU.
        """
        if not self.__version_sent:
            # Mark version as sent
            self.__version_sent = True

            # Send LL_VERSION_IND PDU
            self.send_control(
                BTLE_CTRL() / LL_VERSION_IND(
                    version=self.__llm.stack.bt_version,
                    company=self.__llm.stack.manufacturer_id,
                    subversion=self.__llm.stack.bt_sub_version
                )
            )
'''

class BleConnection(object):

    def __init__(self, l2cap_instance, conn_handle, local_peer_addr, remote_peer_addr):
        self.__l2cap = l2cap_instance
        self.__conn_handle = conn_handle
        self.__remote_peer = remote_peer_addr
        self.__local_peer = local_peer_addr
        self.__version_sent = False
        self.__lock = Lock()

    @property
    def remote_peer(self):
        return self.__remote_peer

    @property
    def local_peer(self):
        return self.__local_peer

    @property
    def conn_handle(self):
        return self.__conn_handle

    @property
    def l2cap(self):
        return self.__l2cap

    @property
    def gatt(self):
        return self.__l2cap.get_layer('gatt')

    @property
    def smp(self):
        return self.__l2cap.get_layer('smp')

    @property
    def phy(self):
        return self.__l2cap.get_layer('phy')

    @property
    def ll(self):
        return self.__l2cap.get_layer('ll')

    @property
    def remote_version(self):
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
        pass

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

    def on_version_ind(self, version):
        """Send back our version info
        """
        if not self.__version_sent:
            self.send_control(
                BTLE_CTRL() / LL_VERSION_IND(
                    version=self.__llm.stack.bt_version,
                    company=self.__llm.stack.manufacturer_id,
                    subversion=self.__llm.stack.bt_sub_version
                )
            )
        self.__version_remote = version

class LinkLayerState(LayerState):

    def __init__(self):
        super().__init__()
        self.connections = {}

    def get_connection(self, conn_handle):
        if conn_handle in self.connections:
            return self.connections[conn_handle]
        else:
            raise IndexError

    def register_connection(self, conn_handle, l2cap_instance, local_peer_addr, remote_peer_addr):
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

    def unregister_connection(self, conn_handle):
        if conn_handle in self.connections:
            del self.connections[conn_handle]

    def get_connection_l2cap(self, conn_handle):
        if conn_handle in self.connections:
            return self.connections[conn_handle]['l2cap']
        return None

    def get_connection_handle(self, l2cap_instance):
        for conn_handle in self.connections:
            if self.connections[conn_handle]['l2cap'] == l2cap_instance:
                return conn_handle
        return

    def register_encryption_key(self, conn_handle, key):
        if conn_handle in self.connections:
            self.connections[conn_handle]['encryption_key'] = key

    def is_authenticated(self, conn_handle):
        if conn_handle in self.connections:
            return self.connections[conn_handle]['authenticated']

    def is_encrypted(self, conn_handle):
        if conn_handle in self.connections:
            return self.connections[conn_handle]['encrypted']

    def mark_as_authenticated(self, conn_handle):
        if conn_handle in self.connections:
            self.connections[conn_handle]['authenticated'] = True

    def mark_as_encrypted(self, conn_handle):
        if conn_handle in self.connections:
            self.connections[conn_handle]['encrypted'] = True

    def get_encryption_key(self, conn_handle):
        if conn_handle in self.connections:
            return self.connections[conn_handle]['encryption_key']
        return None

    def register_skd_and_iv(self, conn_handle, skd, iv):
        if conn_handle in self.connections:
            self.connections[conn_handle]['skd'] = skd
            self.connections[conn_handle]['iv'] = iv


    def get_skd_and_iv(self, conn_handle):
        if conn_handle in self.connections:
            skd = self.connections[conn_handle]['skd']
            iv = self.connections[conn_handle]['iv']
            return (skd, iv)
        return (None, None)

    def register_rand_and_ediv(self, conn_handle, rand, ediv):
        if conn_handle in self.connections:
            self.connections[conn_handle]['rand'] = rand
            self.connections[conn_handle]['ediv'] = ediv

    def get_rand_and_ediv(self, conn_handle):
        if conn_handle in self.connections:
            rand = self.connections[conn_handle]['rand']
            ediv = self.connections[conn_handle]['ediv']
            return (rand, ediv)
        return (None, None)

    def mark_version_sent(self, conn_handle):
        if conn_handle in self.connections:
            self.connections[conn_handle]['version_sent'] = True

    def is_version_sent(self, conn_handle):
        if conn_handle in self.connections:
            self.connections[conn_handle]['version_sent']
        return False

    def set_version_remote(self, conn_handle, version):
        if conn_handle in self.connections:
            self.connections[conn_handle]['version_remote'] = version

    def get_version_remote(self, conn_handle):
        if conn_handle in self.connections:
            return self.connections[conn_handle]['version_remote']

@alias('ll')
@state(LinkLayerState)
class LinkLayer(Layer):

    def configure(self, options={}):
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
            logger.info('[llm] registers new connection %d with %s' % (conn_handle, remote_peer_addr))

            # Instantiate a L2CAP layer (contextual) to handle the connection
            conn_l2cap = self.instantiate(L2CAPLayer)
            conn_l2cap.set_conn_handle(conn_handle)

            # Update state with new connection
            self.state.register_connection(conn_handle, conn_l2cap.name, local_peer_addr, remote_peer_addr)

            # Return connection object
            return BleConnection(
                conn_l2cap,
                conn_handle,
                local_peer_addr,
                remote_peer_addr
            )
        else:
            logger.error('[!] Connection already exists')

            # Return connection object
            return BleConnection(
                self,
                conn_handle,
                local_peer_addr,
                remote_peer_addr
            )

    def on_disconnect(self, conn_handle):
        # Free the previously instantiated L2CAP layer
        conn_layer = self.state.get_connection_l2cap(conn_handle)
        if conn_layer is not None:
            self.destroy(self.get_layer(conn_layer))

        # Remove connection from our registered connections
        self.state.unregister_connection(conn_handle)

    @source('phy', 'data')
    def on_data_pdu_recv(self, pdu, conn_handle=None):
        """We received a DATA PDU.
        """
        # Count PDU
        if conn_handle in self.state.connections:
            conn_metadata = self.state.get_connection(conn_handle)
            conn_metadata['nb_pdu_recvd'] += 1

        # We received a data PDU
        self.on_data_pdu(pdu, conn_handle)

    @source('phy', 'control')
    def on_ctrl_pdu_recv(self, pdu, tag=None, conn_handle=None):
        """We received a CTRL PDU.
        """
        # Count PDU
        if conn_handle in self.state.connections:
            conn_metadata = self.state.get_connection(conn_handle)
            conn_metadata['nb_pdu_recvd'] += 1

        # We received a control PDU
        self.on_ctrl_pdu(pdu, conn_handle)

    def on_ctrl_pdu(self, pdu, conn_handle):
        if conn_handle in self.state.connections:
            ctrl = pdu.getlayer(BTLE_CTRL)
            if ctrl.opcode in self.__handlers:
                self.__handlers[int(ctrl.opcode)](conn_handle, ctrl.getlayer(1))
        else:
            logger.error('[!] Unknown connection handle: %d', conn_handle)


    def on_data_pdu(self, pdu, conn_handle):
        """Forward data PDU to upper layer (L2CAP)
        """
        # We look for the corresponding L2CAP layer instance
        l2cap_layer = self.state.get_connection_l2cap(conn_handle)
        if l2cap_layer is not None:
            self.send(l2cap_layer, bytes(pdu.payload), fragment=(pdu.LLID == 0x1))

    @instance('l2cap')
    def on_l2cap_send_data(self, instance, data, fragment=False, encrypt=None):
        '''L2CAP data encapsulation

        This method retrieves the connection handle corresponding to the instance
        that wants to send data and build a BTLE_DATA packet to send to the PHY
        layer.
        '''
        # Retrieve connection handle corresponding to the instance
        conn_handle = self.state.get_connection_handle(instance)
        if conn_handle is not None:
            logger.debug('sending l2cap data PDU for conn_handle %d' % conn_handle)
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
            logger.error('no connection handle found for L2CAP instance %s' % instance)

    def send_ctrl_pdu(self, conn_handle, pdu, encrypt=None):
        """Send a control PDU to the underlying PHY layer.
        """
        self.send('phy', BTLE_DATA()/BTLE_CTRL()/pdu, tag='control', conn_handle=conn_handle, encrypt=encrypt)

    """Control PDU handlers
    """

    ### Link-layer control PDU callbacks

    def on_unsupported_opcode(self, conn_handle, opcode):
        self.send_ctrl_pdu(
            conn_handle,
            LL_UNKNOWN_RSP(code=opcode)
        )

    def on_connection_update_req(self, conn_handle, conn_update):
        """Connection update is not supported yet
        """
        self.on_unsupported_opcode(conn_handle, CONNECTION_UPDATE_REQ)

    def on_channel_map_req(self, conn_handle, channel_map):
        """Channel map update is not supported yet
        """
        self.on_unsupported_opcode(conn_handle, CHANNEL_MAP_REQ)

    def on_terminate_ind(self, conn_handle, terminate):
        """Terminate this connection
        """
        # Connection has been terminated
        conn = self.state.get_connection(conn_handle)
        if conn is not None:
            self.on_disconnect(conn_handle)

    def start_encryption(self, conn_handle, rand, ediv):
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

    def on_enc_rsp(self, conn_handle, enc_rsp):
        """Encryption response handler
        """
        # Retrieve connection handle corresponding to the instance

        encryption_key = None
        if conn_handle is not None:
            encryption_key = self.state.get_encryption_key(conn_handle)


        # Allowed if we have already negociated an STK
        if encryption_key is not None and conn_handle is not None:

            skdm, ivm = self.state.get_skd_and_iv(conn_handle)
            rand, ediv = self.state.get_rand_and_ediv(conn_handle)

            logger.info('[llm] Received LL_ENC_RSP: skds=%s ivs=%s' % (
                hexlify(pack('<Q', enc_rsp.skds)),
                hexlify(pack('<I', enc_rsp.ivs)),
            ))

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

            logger.info('[llm] master  skd: %s' % hexlify(master_skd))
            logger.info('[llm] master   iv: %s' % hexlify(master_iv))
            logger.info('[llm] slave   skd: %s' % hexlify(slave_skd))
            logger.info('[llm] slave    iv: %s' % hexlify(slave_iv))
            logger.info('[llm] Session  TK: %s' % hexlify(encryption_key))
            logger.info('[llm] Session  iv: %s' % hexlify(iv))
            logger.info('[llm] Exp. Ses iv: %s' % hexlify(self.__llcm.iv))
            logger.info('[llm] Session key: %s' % hexlify(session_key))


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


    def on_enc_req(self, conn_handle, enc_req):
        """Encryption request handler
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

            logger.info('[llm] Received LL_ENC_REQ: rand=%s ediv=%s skd=%s iv=%s' % (
                hexlify(pack('<Q', enc_req.rand)),
                hexlify(pack('<H', enc_req.ediv)),
                hexlify(pack('<Q', enc_req.skdm)),
                hexlify(pack('<I', enc_req.ivm)),
            ))

            logger.info('[llm] Initiate connection LinkLayerCryptoManager')

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

            logger.info('[llm] master  skd: %s' % hexlify(master_skd))
            logger.info('[llm] master   iv: %s' % hexlify(master_iv))
            logger.info('[llm] slave   skd: %s' % hexlify(slave_skd))
            logger.info('[llm] slave    iv: %s' % hexlify(slave_iv))
            logger.info('[llm] Session  TK: %s' % hexlify(encryption_key))
            logger.info('[llm] Session  iv: %s' % hexlify(iv))
            logger.info('[llm] Exp. Ses iv: %s' % hexlify(self.__llcm.iv))
            logger.info('[llm] Session key: %s' % hexlify(session_key))
            skdm, ivm = self.state.get_skd_and_iv(conn_handle)
            logger.info('[llm] Send LL_ENC_RSP: skd=%s iv=%s' % (
                hexlify(pack('<Q', skdm)),
                hexlify(pack('<I', ivm))
            ))

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

    def on_start_enc_req(self, conn_handle, start_enc_req):
        """Encryption start request handler.
        """

        # Start encryption (STK as LTK)
        self.send_ctrl_pdu(
            conn_handle,
            LL_START_ENC_RSP()
        )

    def on_start_enc_rsp(self, conn_handle, start_enc_rsp):
        """Encryption start response handler

        Normally, we get this packet when a link has successfully
        been encrypted (with STK or LTK). So we need to notify the
        SMP that encryption has been acknowledged by the remote peer.


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

    def on_unknown_rsp(self, conn_handle, unk_rsp):
        pass

    def on_feature_req(self, conn_handle, feature_req):
        """Features not supported yet
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

    def on_feature_rsp(self, conn_handle, feature_rsp):
        """Features not supported yet
        """
        self.on_unsupported_opcode(conn_handle, FEATURE_RSP)

    def on_pause_enc_req(self, conn_handle, pause_enc_req):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(conn_handle, PAUSE_ENC_REQ)

    def on_pause_enc_rsp(self, conn_handle, pause_enc_rsp):
        """Encryption not supported yet
        """
        self.on_unsupported_opcode(conn_handle, PAUSE_ENC_RSP)

    def on_version_ind(self, conn_handle, version):
        """Send back our version info
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

    def on_reject_ind(self, conn_handle, reject):
        pass

    def on_slave_feature_req(self, conn_handle, feature_req):
        self.on_unsupported_opcode(conn_handle, SLAVE_FEATURE_REQ)

    def on_connection_param_req(self, conn_handle, conn_param_req):
        self.on_unsupported_opcode(conn_handle, CONNECTION_PARAM_REQ)

    def on_connection_param_rsp(self, conn_handle, conn_param_rsp):
        pass

    def on_reject_ind_ext(self, conn_handle, reject_ext):
        pass

    def on_ping_req(self, conn_handle, ping_req):
        self.on_unsupported_opcode(conn_handle, PING_REQ)

    def on_ping_rsp(self, conn_handle, ping_rsp):
        pass

    def on_length_req(self, conn_handle, length_req):
        """Received a length request PDU
        """
        self.on_unsupported_opcode(conn_handle, LENGTH_REQ)

    def on_length_rsp(self, conn_handle, length_rsp):
        pass

LinkLayer.add(L2CAPLayer)
