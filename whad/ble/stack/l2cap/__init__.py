"""
Bluetooth LE Stack L2CAP manager
"""
from struct import unpack, pack
from scapy.layers.bluetooth import L2CAP_Hdr, ATT_Hdr, SM_Hdr, L2CAP_CmdHdr, \
    L2CAP_Connection_Parameter_Update_Request, L2CAP_Connection_Parameter_Update_Response
from whad.ble.stack.att import ATTLayer
from whad.ble.stack.smp import SMPLayer

from whad.common.stack import Layer, alias, source, state, LayerState, ContextualLayer

import logging
logger = logging.getLogger(__name__)

@alias('l2cap')
class L2CAPLayer(ContextualLayer):

    def configure(self, options={}):
        # Initialize state
        self.state.conn_handle = None
        self.state.local_mtu = 23
        self.state.remote_mtu = 23
        self.state.fifo = None
        self.state.expected_len = 0

    def set_conn_handle(self, conn_handle):
        '''Save current connection handle
        '''
        self.state.conn_handle = conn_handle

    def get_conn_handle(self):
        """Retrieve current connection handle
        """
        return self.state.conn_handle

    def set_local_mtu(self, mtu):
        '''Set local MTU
        '''
        logger.debug('local MTU changed to %d for conn_handle %d' % (mtu, self.state.conn_handle))
        self.state.local_mtu = mtu

    def set_remote_mtu(self, mtu):
        '''Set remote MTU
        '''
        logger.debug('remote MTU changed to %d for conn_handle %d' % (mtu, self.state.conn_handle))
        self.state.remote_mtu = mtu

    def get_local_mtu(self):
        return self.state.local_mtu

    @source('ll')
    def on_data_received(self, l2cap_data, fragment=False):
        """Handles incoming L2CAP data"""
        if fragment and self.state.fifo is not None:
            logger.debug('[l2cap] Received a L2CAP fragment of %d bytes' % len(l2cap_data))
            self.state.fifo += l2cap_data
            logger.debug('[l2cap] L2CAP packet size so far: %d' % len(self.state.fifo))

            if len(self.state.fifo) >= self.state.expected_len:
                # We have received a complete L2CAP packet, process it
                logger.debug('[l2cap] Received a complete L2CAP packet, process it')
                self.on_l2cap_packet(L2CAP_Hdr(self.state.fifo[:self.state.expected_len]))
                self.state.fifo = None

        elif len(l2cap_data) >= 2:
            # Start of L2CAP or complete L2CAP message
            self.state.fifo = l2cap_data
            logger.debug('[l2cap] received start of fragmented or complete message')

            # Check if we have a complete L2CAP message
            self.state.expected_len = unpack('<H', self.state.fifo[:2])[0] + 4
            logger.debug('[l2cap] expected l2cap length: %d' % self.state.expected_len)
            logger.debug('[l2cap] actual l2cap length: %d' % len(self.state.fifo))
            if len(self.state.fifo) >= self.state.expected_len:
                # We have received a complete L2CAP packet, process it
                logger.debug('[l2cap] Received a complete L2CAP packet, process it')
                self.on_l2cap_packet(L2CAP_Hdr(self.state.fifo[:self.state.expected_len]))
                self.state.fifo = None


    def on_l2cap_packet(self, packet):
        """Process incoming L2CAP packets.
        """
        if ATT_Hdr in packet:
            self.send('att', packet.getlayer(ATT_Hdr))
        elif L2CAP_CmdHdr in packet:
            self.on_cmd_packet(packet.getlayer(L2CAP_CmdHdr))
        elif SM_Hdr in packet:
            self.send('smp', packet.getlayer(SM_Hdr))

    def on_cmd_packet(self, packet):
        """Handle L2CAP Connection Parameter Update Requests.

        This command is rejected by default.
        """
        if L2CAP_Connection_Parameter_Update_Request in packet:
            logger.debug('[l2cap] Received a L2CAP Connection Parameter Update Request, rejecting')
            # Reject it
            self.send('ll', L2CAP_Hdr()/L2CAP_CmdHdr(id=packet[L2CAP_CmdHdr].id)/L2CAP_Connection_Parameter_Update_Response(move_result=1))

    def get_fragments(self, data):
        packets=[]
        # If data is bigger than MTU-1, then split
        if len(data) > self.state.remote_mtu:
            nb_packets = int(len(data)/(self.state.remote_mtu - 1))
            if nb_packets * (self.state.remote_mtu - 1) < len(data):
                nb_packets += 1
            raw_data = bytes(data)
            for i in range(nb_packets):
                packets.append(raw_data[i*(self.state.remote_mtu - 1):(i+1)*(self.state.remote_mtu - 1)])
        else:
            nb_packets = 1
            packets = [
                data
            ]
        return packets

    @source('att')
    def on_att_packet_recv(self, data, channel='attribute'):
        """Process incoming packets from ATT that must be forwarded to link layer.
        """
        packets = self.get_fragments(data)

        # Send packets
        for i, pkt in enumerate(packets):
            # First packet is sent with no fragment flag
            if i == 0:
                # Send packet to link layer
                self.send('ll', L2CAP_Hdr(cid=channel, len=len(data))/pkt, fragment=False)
            else:
                # Send packet to link layer
                self.send('ll', pkt, fragment=True)


    @source('smp')
    def on_smp_packet_recv(self, data, channel=0x06):
        """Process incoming packets from ATT that must be forwarded to link layer.
        """
        # Note: we are forced to hardcode the channel in parameters here, because
        # scapy does not provide a complete dictionary mapping 0x06 to 'smp'.

        packets = self.get_fragments(data)

        # Send packets
        for i, pkt in enumerate(packets):
            # First packet is sent with no fragment flag
            if i == 0:
                # Send packet to link layer
                self.send('ll', L2CAP_Hdr(cid=channel, len=len(data))/pkt, fragment=False)
            else:
                # Send packet to link layer
                self.send('ll', pkt, fragment=True)

L2CAPLayer.add(ATTLayer)
L2CAPLayer.add(SMPLayer)
