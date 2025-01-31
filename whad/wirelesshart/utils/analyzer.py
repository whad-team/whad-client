from whad.common.analyzer import TrafficAnalyzer
from whad.scapy.layers.wirelesshart import WirelessHart_Write_Modify_Session_Command_Request, \
     WirelessHart_Transport_Layer_Hdr, WirelessHart_Write_Device_Nickname_Request, \
     WirelessHart_Write_Network_Key_Request
from struct import pack 

class WirelessHartNetworkKeyDistribution(TrafficAnalyzer):
    KEYS = []
    def __init__(self):
        self.reset()
        self.network_key = None

    def process_packet(self, packet):
        if WirelessHart_Transport_Layer_Hdr in packet and hasattr(packet, "commands"):
            commands = packet[WirelessHart_Transport_Layer_Hdr].commands
            
            for command in commands:
                if WirelessHart_Write_Network_Key_Request in command:
                    if command.key_value not in WirelessHartNetworkKeyDistribution.KEYS:
                        self.trigger()
                        self.network_key = command.key_value
                        self.mark_packet(packet)
                        WirelessHartNetworkKeyDistribution.KEYS.append(self.network_key)
                        self.complete()

    @property
    def output(self):
        return {
            "network_key" : self.network_key
        }


    @property
    def key(self):
        if self.network_key is not None:
            return self.network_key
        else:
            return None


    def reset(self):
        super().reset()
        self.network_key = None

class WirelessHartSessionKeyDistribution(TrafficAnalyzer):
    SESSIONS = {}
    def __init__(self):
        self.reset()
        self.session_key = None
        self.session_type = None
        self.destination_address = None
        self.destination_address_type = None
        self.destination_nickname = None
        self.source_nickname = None
        self.peer_unique_id = None
        self.peer_nonce_counter_value = None

    def process_packet(self, packet):
        if WirelessHart_Transport_Layer_Hdr in packet and hasattr(packet, "commands"):
            commands = packet[WirelessHart_Transport_Layer_Hdr].commands
            for command in commands:
                if WirelessHart_Write_Modify_Session_Command_Request in command:
                    if (command.nickname, packet.dest_addr, command.session_type)  not in WirelessHartSessionKeyDistribution.SESSIONS or WirelessHartSessionKeyDistribution.SESSIONS[(command.nickname, packet.dest_addr, command.session_type)] != command.key_value:
                        self.trigger()
                    
                        self.destination_address = packet.dest_addr
                        self.destination_address_type = packet.fcf_destaddrmode

                        self.mark_packet(packet)
                        self.session_key = command.key_value
                        self.session_type = command.session_type
                        self.source_nickname = command.nickname
                        self.peer_unique_id = command.peer_unique_id
                        self.peer_nonce_counter_value = command.peer_nonce_counter_value
                    
                        WirelessHartSessionKeyDistribution.SESSIONS[(command.nickname, packet.dest_addr, command.session_type)] = command.key_value
                
                if WirelessHart_Write_Device_Nickname_Request in command and self.triggered:
                    self.destination_address = packet.dest_addr
                    self.destination_address_type = packet.fcf_destaddrmode
                    self.mark_packet(packet)
                    self.destination_nickname = command.nickname

                if self.triggered and self.session_key is not None:
                    self.complete()
                

    @property
    def output(self):
        return {
            "session_key":self.session_key,
            "session_type":("unicast" if self.session_type else "broadcast"),
            "destination_address":(
                                    (":".join(["{:02x}".format(i) for i in pack('>Q', self.destination_address)])) if
                                    self.destination_address_type == 3 else
                                    "0x{:04x}".format(self.destination_address)
            ), 
            "destination_nickname": "0x{:04x}".format(self.destination_nickname), 
            "source_nickname": "0x{:04x}".format(self.source_nickname), 
            "peer_unique_id":self.peer_unique_id, 
            "peer_nonce_counter_value":self.peer_nonce_counter_value
        }

    @property
    def key(self):
        if (
            self.session_key is not None or
            self.session_type is not None or
            self.destination_nickname is not None or 
            self.source_nickname is not None or
            self.peer_unique_id is not None or 
            self.peer_nonce_counter_value is not None 
        ):
            return self.session_key
        else:
            return None

def reset(self):
        super().reset()
        self.session_key = None
        self.session_type = None
        self.destination_address = None
        self.destination_nickname = None
        self.source_nickname = None
        self.peer_unique_id = None
        self.peer_nonce_counter_value = None
        self.destination_address_type = None




analyzers = {
    "session_keys_distribution" : WirelessHartSessionKeyDistribution,
    "network_key_distribution" : WirelessHartNetworkKeyDistribution
}
