"""
Pythonic Bluetooth LE stack
"""
from .llm import LinkLayer
from .constants import BtVersion

from whad.common.stack import Layer, alias, source

import logging
logger = logging.getLogger(__name__)

@alias('phy')
class BleStack(Layer):

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
        '''BLE connection callback.
        '''
        # Call the LL layer object's `on_connect()` method to give it all the
        # required information
        connection = self.get_layer('ll').on_connect(
            conn_handle,
            local_peer_addr,
            remote_peer_addr
        )

        # Tell the WHAD connector we have a new connection.
        self.__connector.on_new_connection(connection)

    def on_disconnection(self, conn_handle, reason):
        '''BLE disconnection callback.
        '''
        # Notify link layer that a connection has been terminated.
        self.get_layer('ll').on_disconnect(conn_handle)

    def on_ctl_pdu(self, conn_handle, pdu):
        '''Control PDU callback.

        This callback handles a control PDU received from a connection
        identified by its connection handle `conn_handle`.
        '''
        logger.debug('received a control PDU (%d bytes) for connection handle %d' % (len(pdu), conn_handle))
        # Notify link layer we received a control PDU for a given `conn_handle`.
        self.send('ll', pdu, tag='control', conn_handle=conn_handle)


    def on_data_pdu(self, conn_handle, pdu):
        '''Data PDU callback.

        This callback hanles a data PDU received from a connection identitied
        by its connection handle `conn_handle`.
        '''
        logger.debug('received a data PDU (%d bytes) for conn_handle %d' % (len(pdu), conn_handle))
        # Notify link layer we received a data PDU for a given `conn_handle`.
        self.send('ll', pdu, tag='data', conn_handle=conn_handle)

    @source('ll', 'data')
    def send_data(self, data, conn_handle=None, encrypt=None):
        '''Send data to the underlying WHAD connector.
        '''
        logger.debug('sending a data PDU (%d bytes) to conn_handle %d' % (len(data), conn_handle))
        return self.__connector.send_data_pdu(data, conn_handle=conn_handle, encrypt=encrypt)

    @source('ll', 'control')
    def send_control(self, pdu, conn_handle=None, encrypt=None):
        '''Send control PDU to the underlying WHAD connector.
        '''
        logger.debug('sending a control PDU (%d bytes) to conn_handle %d' % (len(pdu), conn_handle))
        self.__connector.send_ctrl_pdu(pdu, conn_handle, encrypt=encrypt)

    def set_encryption(self, conn_handle=None, enabled=True,ll_key=None, ll_iv=None, key=None, rand=None, ediv=None):
        '''Enable or disable encryption using underlying WHAD connector.
        '''
        logger.debug('%s encryption (key=%s, iv=%s)' % ("enabling" if enabled else "disabling", ll_key.hex(), ll_iv.hex()))
        self.__connector.set_encryption(
            conn_handle=conn_handle,
            enabled=enabled,
            ll_key=ll_key,
            ll_iv=ll_iv,
            key=key,
            rand=rand,
            ediv=ediv
        )

BleStack.add(LinkLayer)
