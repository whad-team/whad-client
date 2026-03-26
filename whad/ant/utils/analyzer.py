from whad.common.analyzer import TrafficAnalyzer
from whad.scapy.layers.ant import ANT_FS_Beacon_Packet, ANT_FS_Download_Request_Command_Packet, ANT_FS_Download_Request_Response_Packet
from whad.ant.converters.directory import Directory
from struct import unpack

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
    
}
