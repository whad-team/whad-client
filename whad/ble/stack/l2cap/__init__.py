"""
Bluetooth LE Stack L2CAP manager
"""
from struct import unpack, pack
from scapy.layers.bluetooth import L2CAP_Hdr, ATT_Hdr, SM_Hdr, L2CAP_CmdHdr, \
    L2CAP_Connection_Parameter_Update_Request, L2CAP_Connection_Parameter_Update_Response
from whad.ble.stack.att import BleATT
from whad.ble.stack.smp import BleSMP

from whad.common.stack import StackLayer, layer_alias, match_source, layer_state, StackLayerState

import logging
logger = logging.getLogger(__name__)


class L2CAPState(StackLayerState):

    FIELDS = ['flows']

    def __init__(self):
        super().__init__()
        self.flows = {}

    def register_flow(self, conn_handle):
        self.flows[conn_handle] = {
            'local_mtu': 23,    # Local MTU
            'remote_mtu': 23,   # Remote MTU
            'fifo': None,    # Incoming data (may be incomplete)
            'expected_len': 0
        }
        return self.flows[conn_handle]

    def get_flow(self, conn_handle):
        if conn_handle in self.flows:
            return self.flows[conn_handle]
        return None
    
    def get_remote_mtu(self, conn_handle):
        flow = self.get_flow(conn_handle)
        if flow is not None:
            return flow['remote_mtu']
        else:
            return None
    
    def set_remote_mtu(self, conn_handle, mtu):
        flow = self.get_flow(conn_handle)
        if flow is not None:
            flow['remote_mtu'] = mtu

    def get_local_mtu(self, conn_handle):
        flow = self.get_flow(conn_handle)
        if flow is not None:
            return flow['local_mtu']
        else:
            return None

    def set_local_mtu(self, conn_handle, mtu):
        flow = self.get_flow(conn_handle)
        if flow is not None:
            flow['local_mtu'] = mtu

    def reset_fifo(self, conn_handle):
        flow = self.get_flow(conn_handle)
        if flow is not None:
            flow['fifo'] = None

    def get_fifo(self, conn_handle):
        flow = self.get_flow(conn_handle)
        if flow is not None:
            return flow['fifo']
        return b''
    
    def get_data_size(self, conn_handle):
        flow = self.get_flow(conn_handle)
        if flow is not None:
            if flow['fifo'] is None:
                return 0
            else:
                return len(flow['fifo'])

    def append_data(self, conn_handle, data):
        flow = self.get_flow(conn_handle)
        if flow is not None:
            if flow['fifo'] is None:
                flow['fifo'] = data
            else:
                flow['fifo'] += data

@layer_alias('l2cap')
class NewL2CAPLayer(StackLayer):

    def configure(self, options={}):
        pass

    def set_remote_mtu(self, conn_handle, mtu):
        self.state.set_remote_mtu(conn_handle, mtu)
        
    @match_source('ll')
    def on_data_received(self, l2cap_data, fragment=False, conn_handle=None):
        flow = self.state.get_flow(conn_handle)
        if flow is None:
            flow = self.state.register_flow(conn_handle)
           
        """Handles incoming L2CAP data"""
        if fragment and flow['fifo'] is not None:
            logger.debug('[l2cap] Received a L2CAP fragment of %d bytes' % len(l2cap_data))
            self.state.append_data(conn_handle, l2cap_data)
            logger.debug('[l2cap] L2CAP packet size so far: %d' % len(flow['fifo']))

            if len(flow['fifo']) >= flow['expected_len']:
                # We have received a complete L2CAP packet, process it
                logger.debug('[l2cap] Received a complete L2CAP packet, process it')
                self.on_l2cap_packet(L2CAP_Hdr(flow['fifo'][:flow['expected_len']]))
                flow['fifo'] = None

        elif len(l2cap_data) >= 2:
            # Start of L2CAP or complete L2CAP message
            flow['fifo'] = l2cap_data
            logger.debug('[l2cap] received start of fragmented or complete message')
            
            # Check if we have a complete L2CAP message
            flow['expected_len'] = unpack('<H', flow['fifo'][:2])[0] + 4
            logger.debug('[l2cap] expected l2cap length: %d' % flow['expected_len'])
            logger.debug('[l2cap] actual l2cap length: %d' % len(flow['fifo']))
            
            if len(flow['fifo']) >= flow['expected_len']:
                # We have received a complete L2CAP packet, process it
                logger.debug('[l2cap] Received a complete L2CAP packet, process it')
                self.on_l2cap_packet(L2CAP_Hdr(flow['fifo'][:flow['expected_len']]))
                flow['fifo'] = None


    def on_l2cap_packet(self, packet):
        """Process incoming L2CAP packets.
        """
        """
        if ATT_Hdr in packet:
            self.__att.on_packet(packet.getlayer(ATT_Hdr))
        elif SM_Hdr in packet:
            self.__smp.on_smp_packet(packet.getlayer(SM_Hdr))
        elif L2CAP_CmdHdr in packet:
            self.on_cmd_packet(packet.getlayer(L2CAP_CmdHdr))
        """

    def on_cmd_packet(self, packet):
        """Handle L2CAP Connection Parameter Update Requests.

        This command is rejected by default.
        """
        if L2CAP_Connection_Parameter_Update_Request in packet:
            logger.debug('[l2cap] Received a L2CAP Connection Parameter Update Request, rejecting')
            
            # Reject this request
            self.__connection.lock()
            self.__connection.send_l2cap_data(
                L2CAP_Hdr()/L2CAP_CmdHdr(id=packet[L2CAP_CmdHdr].id)/L2CAP_Connection_Parameter_Update_Response(move_result=1)
            )
            self.__connection.unlock()


class BleL2CAP(object):

    def __init__(self, connection):
        self.__connection = connection
        self.__packet = None
        self.__expected_length = 0
        self.__att = BleATT(self)
        self.__smp = BleSMP(self)

        # Set ATT GATT layer based on connection GATT class instance
        self.__att.gatt = self.__connection.gatt_class

        # Default MTU for L2CAP: 23 bytes
        self.__remote_mtu = 23
        self.__local_mtu = 23


    @property
    def smp(self):
        return self.__smp


    @property
    def connection(self):
        return self.__connection


    @property
    def att(self):
        return self.__att


    @property
    def gatt(self):
        return self.__att.gatt


    @property
    def remote_mtu(self):
        return self.__remote_mtu


    @remote_mtu.setter
    def remote_mtu(self, mtu):
        self.__remote_mtu = mtu


    @property
    def local_mtu(self):
        return self.__local_mtu

    @local_mtu.setter
    def local_mtu(self, mtu):
        self.__local_mtu = mtu


    def on_data_received(self, l2cap_data, fragment=False):
        """Handles incoming L2CAP data"""
        if fragment and self.__packet is not None:
            logger.debug('[l2cap] Received a L2CAP fragment of %d bytes' % len(l2cap_data))
            self.__packet += l2cap_data
            logger.debug('[l2cap] L2CAP packet size so far: %d' % len(self.__packet))

            if len(self.__packet) >= self.__expected_length:
                # We have received a complete L2CAP packet, process it
                logger.debug('[l2cap] Received a complete L2CAP packet, process it')
                self.on_l2cap_packet(L2CAP_Hdr(self.__packet[:self.__expected_length]))
                self.__packet = None

        elif len(l2cap_data) >= 2:
            # Start of L2CAP or complete L2CAP message
            self.__packet = l2cap_data
            logger.debug('[l2cap] received start of fragmented or complete message')
            
            # Check if we have a complete L2CAP message
            self.__expected_length = unpack('<H', self.__packet[:2])[0] + 4
            logger.debug('[l2cap] expected l2cap length: %d' % self.__expected_length)
            logger.debug('[l2cap] actual l2cap length: %d' % len(self.__packet))
            
            if len(self.__packet) >= self.__expected_length:
                # We have received a complete L2CAP packet, process it
                logger.debug('[l2cap] Received a complete L2CAP packet, process it')
                self.on_l2cap_packet(L2CAP_Hdr(self.__packet[:self.__expected_length]))
                self.__packet = None


    def on_l2cap_packet(self, packet):
        """Process incoming L2CAP packets.
        """
        if ATT_Hdr in packet:
            self.__att.on_packet(packet.getlayer(ATT_Hdr))
        elif SM_Hdr in packet:
            self.__smp.on_smp_packet(packet.getlayer(SM_Hdr))
        elif L2CAP_CmdHdr in packet:
            self.on_cmd_packet(packet.getlayer(L2CAP_CmdHdr))

    def on_cmd_packet(self, packet):
        """Handle L2CAP Connection Parameter Update Requests.

        This command is rejected by default.
        """
        if L2CAP_Connection_Parameter_Update_Request in packet:
            logger.debug('[l2cap] Received a L2CAP Connection Parameter Update Request, rejecting')
            
            # Reject this request
            self.__connection.lock()
            self.__connection.send_l2cap_data(
                L2CAP_Hdr()/L2CAP_CmdHdr(id=packet[L2CAP_CmdHdr].id)/L2CAP_Connection_Parameter_Update_Response(move_result=1)
            )
            self.__connection.unlock()

    def send(self, data, channel='attribute'):
        """Send data
        """
        packets=[]
        # If data is bigger than MTU-1, then split
        if len(data) > self.__remote_mtu:
            nb_packets = int(len(data)/(self.__remote_mtu - 1))
            if nb_packets * (self.__remote_mtu - 1) < len(data):
                nb_packets += 1
            raw_data = bytes(data)
            for i in range(nb_packets):
                packets.append(raw_data[i*(self.__remote_mtu - 1):(i+1)*(self.__remote_mtu - 1)])
        else:
            nb_packets = 1
            packets = [
                data
            ]

        # Send packets
        for i, pkt in enumerate(packets):
            # First packet is sent with no fragment flag
            if i == 0:
                self.__connection.send_l2cap_data(
                    L2CAP_Hdr(cid=channel, len=len(data))/pkt,
                    fragment=False
                )
            else:
                self.__connection.send_l2cap_data(
                    pkt,
                    fragment=True
                )