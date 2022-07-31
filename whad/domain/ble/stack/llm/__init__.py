"""
Bluetooth LE Stack Link-layer Manager
"""

from scapy.layers.bluetooth4LE import *

from whad.domain.ble.stack.l2cap import BleL2CAP

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

class BleConnection(object):

    def __init__(self, llm, conn_handle):
        self.__llm = llm
        self.__conn_handle = conn_handle
        self.__l2cap = BleL2CAP(self)

    def on_l2cap_data(self, data, fragment=False):
        """Forward L2CAP data to L2CAP layer"""
        self.__l2cap.on_data_received(data, fragment)

    def send_l2cap_data(self, data, fragment=False):
        """Sends data back
        """
        self.__llm.send_data(self.__conn_handle, data, fragment)

    def use_gatt_class(self, clazz):
        self.__l2cap.att.use_gatt_class(clazz)

    @property
    def gatt(self):
        return self.__l2cap.att.gatt

class BleLinkLayerManager(object):

    def __init__(self, stack):
        self.__stack = stack
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
        self.__connections = {}

    def on_connect(self, connection):
        """Handles BLE connection
        """
        if connection.conn_handle not in self.__connections:
            print('[llm] registers new connection %d' % connection.conn_handle)
            self.__connections[connection.conn_handle] = BleConnection(
                self,
                connection.conn_handle
            )
            return self.__connections[connection.conn_handle]
        else:
            print('[!] Connection already exists')

    def on_disconnect(self, conn_handle):
        if conn_handle in self.__connections:
            del self.__connections[conn_handle]

    def on_ctl_pdu(self, conn_handle, control):
        """Handles Control PDU
        """
        if conn_handle in self.__connections:
            # Dispatch control PDU based on opcode
            if control.haslayer(BTLE_CTRL):
                ctrl = control.getlayer(BTLE_CTRL)
                if ctrl.opcode in self.__handlers:
                    self.__handlers[int(ctrl.opcode)](ctrl.getlayer(1))
        else:
            print('[!] Wrong connection handle: %d', conn_handle)

    def on_data_pdu(self, conn_handle, data):
        """Manages Data PDU.
        """
        if conn_handle in self.__connections:
            conn = self.__connections[conn_handle]
            conn.on_l2cap_data(bytes(data.payload), data.LLID == 0x1)

    def send_data(self, conn_handle, data, fragment=False):
        """Pack data into a Data PDU and transfer it to the device.
        """
        llid = 0x01 if fragment else 0x02
        self.__stack.send_data(
            conn_handle,
            BTLE_DATA(
                LLID=llid,
                len=len(data)
            )/data
        )

    ### Link-layer control PDU callbacks

    def on_connection_update_req(self, conn_update):
        pass

    def on_channel_map_req(self, channel_map):
        pass

    def on_terminate_ind(self, terminate):
        pass

    def on_enc_req(self, enc_req):
        pass

    def on_enc_rsp(self, enc_rsp):
        pass

    def on_start_enc_req(self, start_enc_req):
        pass

    def on_start_enc_rsp(self, start_enc_rsp):
        pass

    def on_unknown_rsp(self, unk_rsp):
        pass

    def on_feature_req(self, feature_req):
        pass

    def on_feature_rsp(self, feature_rsp):
        pass

    def on_pause_enc_req(self, pause_enc_req):
        pass

    def on_pause_enc_rsp(self, pause_enc_rsp):
        pass

    def on_version_ind(self, version):
        pass

    def on_reject_ind(self, reject):
        pass

    def on_slave_feature_req(self, feature_req):
        pass

    def on_connection_param_req(self, conn_param_req):
        pass

    def on_connection_param_rsp(self, conn_param_rsp):
        pass

    def on_reject_ind_ext(self, reject_ext):
        pass

    def on_ping_req(self, ping_req):
        pass

    def on_ping_rsp(self, ping_rsp):
        pass

    def on_length_req(self, length_req):
        pass

    def on_length_rsp(self, length_rsp):
        pass
