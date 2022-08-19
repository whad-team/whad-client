"""
Bluetooth LE Stack L2CAP manager
"""
from struct import unpack, pack
from scapy.layers.bluetooth import L2CAP_Hdr, ATT_Hdr
from whad.ble.stack.att import BleATT

class BleL2CAP(object):

    def __init__(self, connection):
        self.__connection = connection
        self.__packet = None
        self.__expected_length = 0
        self.__att = BleATT(self)

        # Set ATT GATT layer based on connection GATT class instance
        self.__att.gatt = self.__connection.gatt_class

        # Default MTU for L2CAP: 23 bytes
        self.__remote_mtu = 23
        self.__local_mtu = 23

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
            self.__packet += l2cap_data
        elif len(l2cap_data) >= 2:
            # Start of L2CAP or complete L2CAP message
            self.__packet = l2cap_data
            
            # Check if we have a complete L2CAP message
            self.__expected_length = unpack('<H', self.__packet[:2])[0] + 4
            
            if len(self.__packet) >= self.__expected_length:
                # We have received a complete L2CAP packet, process it
                self.on_l2cap_packet(L2CAP_Hdr(self.__packet[:self.__expected_length]))
            
            self.__packet = None

    def on_l2cap_packet(self, packet):
        """Process incoming L2CAP packets.
        """
        if ATT_Hdr in packet:
            self.__att.on_packet(packet.getlayer(ATT_Hdr))

    def send(self, data):
        """Send data
        """
        packets=[]
        #data.show()
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
                bytes(data)
            ]

        # Send packets
        for i, pkt in enumerate(packets):
            # First packet is sent with no fragment flag
            if i == 0:
                self.__connection.send_l2cap_data(
                    L2CAP_Hdr(cid="attribute", len=len(data))/pkt,
                    fragment=False
                )
            else:
                self.__connection.send_l2cap_data(
                    pkt,
                    fragment=True
                )