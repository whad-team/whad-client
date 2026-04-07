from whad.common.analyzer import TrafficAnalyzer
from whad.scapy.layers.ant import ANT_FS_Beacon_Packet, ANT_FS_Download_Request_Command_Packet, \
    ANT_FS_Download_Request_Response_Packet, ANT_FS_Auth_Command_Packet, ANT_FS_Auth_Response_Packet, ANT_FS_Beacon_Auth_Packet
from whad.ant.converters.directory import Directory
from struct import unpack

class Authentication(TrafficAnalyzer):
    def __init__(self):
        super().__init__()
    
    @property
    def output(self):
        out = {
            "method": self.method,
            "response": self.response, 
            "host_serial":self.host_serial, 
            "client_serial":self.client_serial, 
            "host_auth":self.host_auth, 
            "client_auth":self.client_auth
        }
        return out

    def reset(self):
        super().reset()
        self.method = None
        self.response = None
        self.host_serial = None
        self.client_serial = None
        self.host_auth = None
        self.client_auth = None
        self.remaining_host_string_length = 0
        self.remaining_client_string_length = 0

    def process_packet(self, packet):

        if ANT_FS_Auth_Command_Packet in packet:
            self.trigger()
            self.mark_packet(packet)
            if packet.auth_type == 0:
                self.method = "passthru"
            elif packet.auth_type == 1:
                self.method = "request_serial"
            elif packet.auth_type == 2:
                self.method = "request_pairing"
            elif packet.auth_type == 3:
                self.method = "request_passkey"
            self.host_serial = packet.host_serial
            self.remaining_host_string_length = packet.auth_string_length
            self.host_auth = b""

        elif ANT_FS_Auth_Response_Packet in packet:
            self.mark_packet(packet)
            self.response = 'accept' if packet.response == 1 else 'reject'
            self.client_serial = packet.client_serial
            self.remaining_client_string_length = packet.auth_string_length
            self.client_auth = b""
            if self.remaining_host_string_length == 0 and self.remaining_client_string_length == 0:
                self.complete()

        elif ANT_FS_Beacon_Auth_Packet not in packet and packet.broadcast == 1 and self.remaining_host_string_length > 0:
            self.mark_packet(packet)

            if self.remaining_host_string_length > 8:
                payload = bytes(packet)[7:-2]
            else:
                payload = bytes(packet)[7:7+self.remaining_host_string_length]

            self.host_auth += payload
            self.remaining_host_string_length -= len(payload)



        elif ANT_FS_Beacon_Auth_Packet not in packet and packet.broadcast == 1 and self.remaining_client_string_length > 0:
            self.mark_packet(packet)
            if self.remaining_client_string_length > 8:
                payload = bytes(packet)[7:-2]
            else:
                payload = bytes(packet)[7:7+self.remaining_client_string_length]

            self.client_auth += payload
            self.remaining_client_string_length -= len(payload)

            if self.remaining_host_string_length == 0 and self.remaining_client_string_length == 0:
                self.complete()
                
class Download(TrafficAnalyzer):
    def __init__(self):
        super().__init__()

    @property
    def output(self):
        out = {
            "index" : self.index, 
            "offset" : self.offset, 
            "new_transfer" : self.new_transfer, 
            "crc_seed" : self.crc_seed,
            "max_block_size" : self.max_block_size, 
            "data_offset" : self.data_offset, 
            "file_size" : self.file_size, 
            "crc" : self.crc, 
            "data" : self.data
        }
        if self.directory is not None:
            out["directory"] = self.directory
        return out

    def reset(self):
        super().reset()
        self.data = None
        self.index = None
        self.offset = None
        self.new_transfer = None
        self.crc_seed = None
        self.max_block_size = None
        self.data_offset = None
        self.crc = None
        self.file_size = None
        self.directory = None
        self.data_capture = False
        self.request_capture = False
        self.response_capture = False

    def process_packet(self, packet):
        if ANT_FS_Download_Request_Command_Packet in packet:
            self.trigger()
            self.mark_packet(packet)
            self.index = packet.index
            self.offset = packet.offset
            self.data = b""
            self.request_capture = True
            self.data_capture = False

        elif self.request_capture and packet.broadcast == 1 and packet.end == 1 and packet.packet_type == 0:
            self.mark_packet(packet)
            payload = bytes(packet)[8:-2]
            
            self.new_transfer = (payload[0] == 1)
            self.crc_seed = unpack('H', payload[1:3])[0]
            self.max_block_size = unpack('I', payload[3:])[0]
            self.request_capture = False

        elif ANT_FS_Download_Request_Response_Packet in packet:
            self.mark_packet(packet)
            if packet.response == 0: # ANTFS_OK
                self.response_capture = True
                self.data_capture = True
            else:
                self.reset()

        elif self.data_capture and packet.broadcast == 1:
            if packet.ack == 0:
                payload = bytes(packet)[7:-2]

                if self.response_capture:
                    self.data_offset = unpack('<I', payload[:4])[0]
                    self.file_size = unpack('<I', payload[4:])[0]
                    self.response_capture = False
                elif packet.end == 0:
                    self.data += payload
                else:
                    self.crc = unpack('H', payload[-2:])[0]
                    if self.index == 0:
                        self.directory = Directory(value=self.data)
                    self.complete()
            self.mark_packet(packet)

        elif self.data_capture:
            self.complete()
        '''
        elif ANT_FS_Download_Request_Command_Packet in packet:

            self.mark_packet(packet)

        elif ANT_FS_Beacon_Packet in packet:
            self.data = "toto"
            self.complete()
        '''

analyzers = {
    "download" : Download,
    "authentication" : Authentication
}
