from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import Field, ByteEnumField, StrLenField, StrFixedLenField, IntField, XShortField, LEShortField, \
    FieldLenField, StrLenField, ConditionalField, PacketField, XByteField, XIntField,  SignedShortField, SignedByteField, \
    XShortEnumField, BitEnumField, BitField, ByteField, ShortField, XShortField, PacketListField, FieldListField, IEEEFloatField, \
    ThreeBytesField
#from whad.scapy.layers.wirelesshart_db import EXPANDED_DEVICE_TYPES, MANUFACTURERS_ID_CODES
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS, Dot15d4Data, MultipleTypeField
from scapy.config import conf
from scapy.utils import rdpcap
from math import ceil
from struct import pack, unpack
from calendar import month_abbr
import os.path
import json

def get_db(dbname):
    name = os.path.realpath("{}/ressources/databases/{}.json".format(os.path.dirname(__file__) + "../../../", dbname))
    with open(name, "r") as f:
        return json.loads(f.read())

EXPANDED_DEVICE_TYPES = get_db("expanded_device_codes")
MANUFACTURERS_ID_CODES =  get_db("manufacturers_id_code")

MONTH_TYPE = list(map(str.lower, list(month_abbr)))
YEAR_TYPE = {k : str(k + 1900) for k in range(255)}

class FiveBytesField(ByteField):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, ">Q")

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[int]) -> bytes
        return s + pack(self.fmt, self.i2m(pkt, val))[-5:]

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, int]
        return s[5:], self.m2i(pkt, unpack(self.fmt, b"\x00"*3 + s[:5])[0])  # noqa: E501


class WirelessHart_DataLink_Hdr(Packet):
    name = "Wireless Hart Data Link header"
    fields_desc = [
        BitField("reserved", None, 2), 
        BitEnumField("priority", None, 2, {0 : "alarm", 1:"normal", 2:"process_data", 3 : "command"}), 
        BitEnumField("network_key_use", None, 1, {0 : "no", 1:"yes"}), 
        BitEnumField("pdu_type", None, 3, {0 : "acknowledgment", 1:"advertisement", 2:"keep-alive", 3:"disconnect", 7 : "data"}), 
        XIntField("mic", None),
    ]
    
    def pre_dissect(self,s):
        return s[0:1] + s[-4:] + s[1:-4]

    
    def post_build(self,p,pay):
            return p[0:1] + p[5:] + pay + p[1:5]
    
    def post_dissect(self, s):
        """Override layer post_dissect() function to reset raw packet cache.
        """
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

class Link(Packet):
    name = "Wireless Hart Link"
    fields_desc = [
        ShortField("link_join_slot", None),
        BitField("link_reserved", 0, 1), 
        BitEnumField("link_use_for_transmission", 0, 1, {0:"denied", 1:"allowed"}), 
        BitField("link_channel_offset", 0, 6)
    ]
     
    def extract_padding(self, s):
        return b'', s
   
    
class Superframe(Packet):
    name = "Wireless Hart Superframe"
    fields_desc = [
        ByteField("superframe_id", None), 
        ShortField("superframe_number_of_slots", None), 
        FieldLenField("superframe_number_of_links", None, fmt="B", length_of="superframe_links"), 
        PacketListField("superframe_links",[], Link, length_from=lambda p:3 * p.superframe_number_of_links)

    ]
    
    def extract_padding(self, s):
        return b'', s

class WirelessHart_DataLink_Advertisement(Packet):
    name = "Wireless Hart Data Link Advertisement DLPDU"
    fields_desc = [
        FiveBytesField("asn", 0),
        BitEnumField("security_level_supported",0,4,{0 : "session_keyed", 1 : "join_keyed", 2 : "reserved", 3: "reserved"}), 
        BitField("join_priority",0,4), 
        FieldLenField("channel_count", None, fmt="B", length_of="channel_map"),
        StrLenField("channel_map", None, length_from = lambda p: ceil(p.channel_count / 8)),
        XShortField("graph_id", None), 
        FieldLenField("number_of_superframes", None, fmt="B", count_of="superframes"),
        PacketListField("superframes",[], Superframe, count_from=lambda p:p.number_of_superframes)

    ]

class WirelessHart_DataLink_Acknowledgement(Packet):
    name = "Wireless Hart Data Link Acknowledgement DLPDU"
    fields_desc = [
        ByteEnumField("response_code", None, 
            {   
                0 : "success",
                61 : "error_no_buffers_available",
                62 : "error_no_alarm_event_buffers_available",
                63 : "error_priority_too_low"
            }
        ), 
        SignedShortField("time_adjustment", None)
        
    ]

class WirelessHart_DataLink_KeepAlive(Packet):
    name = "Wireless Hart Data Link Keep Alive DLPDU"
    fields_desc = [] # empty payload

class WirelessHartAddressField(Field):
    __slots__ = ["adjust", "length_of"]

    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        if adjust is not None:
            self.adjust = adjust
        else:
            self.adjust = lambda pkt, x: self.lengthFromAddrMode(pkt, x)

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if len(hex(self.i2m(pkt, x))) < 7:  # short address
            return hex(self.i2m(pkt, x))
        else:  # long address
            x = "%016x" % self.i2m(pkt, x)
            return ":".join(["%s%s" % (x[i], x[i + 1]) for i in range(0, len(x), 2)])  # noqa: E501

    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + pack(">H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + pack(">Q", val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, unpack(">H", s[:2])[0])  # noqa: E501
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, unpack(">Q", s[:8])[0])  # noqa: E501
        else:
            raise Exception('impossible case')

    def lengthFromAddrMode(self, pkt, x):
        addrmode = 0
        pkttop = pkt
        if pkttop is None:
            print("No underlayer to guess address mode")
            return 0
        while True:
            try:
                addrmode = pkttop.getfieldval(x)
                break
            except Exception:
                if pkttop.underlayer is None:
                    break
                pkttop = pkttop.underlayer
        
        if addrmode == 0:
            return 2
        elif addrmode == 1:
            return 8
        return 0


class WirelessHart_Network_Hdr(Packet):
    name = "Wireless Hart Network Layer header"
    fields_desc = [
        BitEnumField("nwk_dest_addr_length", None, 1, {0 : "short", 1 : "long"}), 
        BitEnumField("nwk_src_addr_length", None, 1, {0 : "short", 1 : "long"}), 
        BitField("reserved", 0, 3), 
        BitEnumField("proxy_route", None, 1, {0 : "no", 1 : "yes"}),
        BitEnumField("second_src_route_segment", None, 1, {0 : "no", 1 : "yes"}),
        BitEnumField("first_src_route_segment", None, 1, {0 : "no", 1 : "yes"}), 
        ByteField("ttl", None), 
        XShortField("asn_snippet", None), # least two significant bits of ASN : latency count
        XShortField("graph_id", None),
        WirelessHartAddressField("nwk_dest_addr", 0x0, length_of="nwk_dest_addr_length"),
        WirelessHartAddressField("nwk_src_addr", 0x0, length_of="nwk_src_addr_length"),  
        ConditionalField(
            WirelessHartAddressField("parent_proxy_addr", None, adjust = lambda pkt, x : 2),
            lambda pkt: pkt.proxy_route  == 1
        ),
          ConditionalField(
            FieldListField("first_route_segment",[],WirelessHartAddressField("parent_proxy_addr", None, adjust = lambda pkt, x : 2), count_from=lambda p : 4),
            lambda pkt:pkt.getfieldval("first_src_route_segment") == 1
        ),
          ConditionalField(
            FieldListField("second_route_segment",[],WirelessHartAddressField("parent_proxy_addr", None, adjust = lambda pkt, x : 2), count_from=lambda p : 4),
            lambda pkt:pkt.getfieldval("second_src_route_segment") == 1
        ),
        
    ]

class WirelessHart_Network_Security_SubLayer_Hdr(Packet):
    name = "Wireless Hart Network Security sub-layer header"
    fields_desc = [
        BitField("reserved", 0, 4), 
        BitEnumField("security_types", 0, 4,{0: 'session_keyed', 1: 'join_keyed', 2: 'reserved', 3: 'reserved', 4: 'reserved', 5: 'reserved', 6: 'reserved', 7: 'reserved', 8: 'reserved', 9: 'reserved', 10: 'reserved', 11: 'reserved', 12: 'reserved', 13: 'reserved', 14: 'reserved', 15:'decrypted'}), 
        MultipleTypeField(
            [
                (XByteField("counter", None), lambda p:p.security_types == 0),
            ],
            XIntField("counter", None)
        ),
        XIntField("nwk_mic", None)
]
    
class WirelessHart_Command_Hdr(Packet):
    name = "Wireless Hart Command header"
    fields_desc = [
        XShortField("command_number", None), 
        ByteField("len", None)
    ]
            
    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            p = p[:2] + pack("B", len(pay)) + p[3:]
        return p


class WirelessHart_Command_Request_Hdr(WirelessHart_Command_Hdr):
    name = "Wireless Hart Command Request header"


class WirelessHart_Command_Response_Hdr(WirelessHart_Command_Hdr):
    name = "Wireless Hart Command Response header"
    

class WirelessHart_Transport_Layer_Hdr(Packet):
    name = "Wireless Hart Transport Layer header"
    fields_desc = [
        BitEnumField('acknowledged', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('response', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('broadcast', 0, 1, {0 : "no", 1: "yes"}), 
        BitField('tr_seq_num', 0, 5), 

        # Device status byte
        BitEnumField('device_malfunction', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('configuration_changed', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('cold_start', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('more_status_available', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('loop_current_fixed', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('loop_current_saturated', 0, 1, {0 : "no", 1: "yes"}),
        BitEnumField('non_primary_variable_out_of_limit', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('primary_variable_out_of_limit', 0, 1, {0 : "no", 1: "yes"}),  

        # Extended Device status byte
        BitField('reserved', 0, 2), 
        BitEnumField('function_check', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('out_of_specification', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('failure', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('critical_power_failure', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('device_variable_alert', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('maintenance_required', 0, 1, {0 : "no", 1: "yes"}), 

        MultipleTypeField(
            [
                (PacketListField("commands", [], WirelessHart_Command_Request_Hdr), lambda p:p.response == 0),
            ],
            PacketListField("commands", [], WirelessHart_Command_Response_Hdr)
        ),
    ]
    
class WirelessHart_Command_Payload(Packet):
    name = "Wireless Hart Command Payload"
    fields_desc = []

      
    def extract_padding(self, s):
        return b'', s

   
class WirelessHart_Report_Neighbor_Signal_Level_Command_Request(WirelessHart_Command_Payload):
    name = "Report Neighbor Signal Level Command Request"
    fields_desc = [
        ByteField("neighbor_table_index", None), 
        ByteField("neighbor_entries_number", None), 
    ]

class WirelessHart_Report_Neighbor_Signal_Level_Command_Response(WirelessHart_Command_Payload):
    name = "Report Neighbor Signal Level Command Response"
    fields_desc = [
        ByteField("status", None), # not in spec but seems to be here ? 

        ByteField("neighbor_table_index", None), 
        ByteField("neighbor_entries_number", None), 
        ByteField("neighbors_number", None), 
        XShortField("nickname", None), 
        SignedByteField("rsl", None)
    ]
class WirelessHart_Write_Modify_Session_Command_Request(WirelessHart_Command_Payload):
    name = "Write / modify session Command Request"
    fields_desc = [
        ByteEnumField("session_type", None, {}), 
        XShortField("nickname", None), 
        StrFixedLenField("peer_unique_id", None, length=5),
        IntField("peer_nonce_counter_value", None),
        StrFixedLenField("key_value", None, length=16),
        ByteField("reserved", 0), 
        #FiveBytesField("execution_time", None)
    ]


class WirelessHart_Write_Modify_Session_Command_Response(WirelessHart_Command_Payload):
    name = "Write / modify session Command Response"
    fields_desc = [
        ByteField("status", None), # not in spec but seems to be here ? 

        ByteEnumField("session_type", None, {}), 
        XShortField("nickname", None), 
        StrFixedLenField("peer_unique_id", None, length=5),
        IntField("peer_nonce_counter_value", None),
        StrFixedLenField("key_value", None, length=16),
        ByteField("number_of_sessions_remaining", None), 
        #FiveBytesField("execution_time", None)
    ]


class WirelessHart_Write_Network_Key_Request(WirelessHart_Command_Payload):
    name = "Write Network Key Request"
    fields_desc = [
        StrFixedLenField("key_value", None, length=16),
        #FiveBytesField("execution_time", None)
    ]


class WirelessHart_Write_Network_Key_Response(WirelessHart_Command_Payload):
    name = "Write Network Key Response"
    fields_desc = [
        ByteField("status", None), # not in spec but seems to be here ? 

        StrFixedLenField("key_value", None, length=16),
        #FiveBytesField("execution_time", None)
    ]


class WirelessHart_Write_Device_Nickname_Request(WirelessHart_Command_Payload):
    name = "Write Device Nickname Request"
    fields_desc = [
        XShortField("nickname", None), 
        #FiveBytesField("execution_time", None)
    ]


class WirelessHart_Write_Device_Nickname_Response(WirelessHart_Command_Payload):
    name = "Write Device Nickname Response"
    fields_desc = [
        ByteField("status", None), # not in spec but seems to be here ? 

        XShortField("nickname", None), 
        #FiveBytesField("execution_time", None)
    ]

class WirelessHart_Write_Modify_Superframe_Request(WirelessHart_Command_Payload):
    name = "Write / modify Superframe Request"
    fields_desc = [
            ByteField("superframe_id", None), 
            ShortField("superframe_number_of_slots", None),
            BitEnumField("handheld_superframe", 0, 1, {0 : "no", 1 : "yes"}), 
            BitField("reserved1", 0, 6),  
            BitEnumField("active_superframe", 0, 1, {0 : "no", 1 : "yes"}), 
            ByteField("reserved2", None), 
    ]

class WirelessHart_Write_Modify_Superframe_Response(WirelessHart_Command_Payload):
    name = "Write / modify Superframe Response"
    fields_desc = [
            ByteField("status", None), # not in spec but seems to be here ? 

            ByteField("superframe_id", None), 
            ShortField("superframe_number_of_slots", None),
            BitEnumField("handheld_superframe", 0, 1, {0 : "no", 1 : "yes"}), 
            BitField("reserved1", 0, 6),  
            BitEnumField("active_superframe", 0, 1, {0 : "no", 1 : "yes"}), 
            ByteField("superframe_number_of_remaining_superframes", None), 
    ]



class WirelessHart_Add_Link_Request(WirelessHart_Command_Payload):
    name = "Add Link Request"
    fields_desc = [
        ByteField("superframe_id", None), 
        ShortField("slot_number", None),  # slot number in superframe for this link
        ByteField("channel_offset", None), # channel offset of this link 
        XShortField("neighbor_nickname", None), # nickname of neighbor for this link 

        # Link option flag codes
        BitField("reserved", 0, 5),
        BitEnumField("shared", 0, 1, {0 : "no", 1 : "yes"}), 
        BitEnumField("receive", 0, 1, {0 : "no", 1 : "yes"}), 
        BitEnumField("transmit", 0, 1, {0 : "no", 1 : "yes"}), 

        # Link type
        ByteEnumField("link_type", None, {0: "normal", 1: "discovery", 2: "broadcast", 3: "join"})
    ]


class WirelessHart_Add_Link_Response(WirelessHart_Command_Payload):
    name = "Add Link Response"
    fields_desc = [
        ByteField("status", None), 

        ByteField("superframe_id", None), 
        ShortField("slot_number", None),  # slot number in superframe for this link
        ByteField("channel_offset", None), # channel offset of this link 
        XShortField("neighbor_nickname", None), # nickname of neighbor for this link 

        # Link option flag codes
        BitField("reserved", 0, 5),
        BitEnumField("shared", 0, 1, {0 : "no", 1 : "yes"}), 
        BitEnumField("receive", 0, 1, {0 : "no", 1 : "yes"}), 
        BitEnumField("transmit", 0, 1, {0 : "no", 1 : "yes"}), 

        # Link type
        ByteEnumField("link_type", None, {0: "normal", 1: "discovery", 2: "broadcast", 3: "join"}), 
        ShortField("number_of_remaining_link_entries", None)
    ]



class WirelessHart_Write_Neighbor_Property_Flag_Request(WirelessHart_Command_Payload):
    name = "Write Neighbor Property Flag Request"
    fields_desc = [
        XShortField("neighbor_nickname", None), 

        BitEnumField("no_links", 0, 1, {0 : "no", 1 : "yes"}), 
        BitField("reserved", 0, 6), 
        BitEnumField("time_source", 0, 1, {0 : "no", 1 : "yes"}), 

    ]


class WirelessHart_Write_Neighbor_Property_Flag_Response(WirelessHart_Command_Payload):
    name = "Write Neighbor Property Flag Response"
    fields_desc = [
        ByteField("status", None), 
        
        XShortField("neighbor_nickname", None), 

        BitEnumField("no_links", 0, 1, {0 : "no", 1 : "yes"}), 
        BitField("reserved", 0, 6), 
        BitEnumField("time_source", 0, 1, {0 : "no", 1 : "yes"}), 

    ]



class WirelessHart_Read_Wireless_Device_Capabilities_Request(WirelessHart_Command_Payload):
    name = "Read Wireless Device Capabilities Request"
    fields_desc = []


class WirelessHart_Read_Wireless_Device_Capabilities_Response(WirelessHart_Command_Payload):
    name = "Read Wireless Device Capabilities Response"
    
    fields_desc = [
        ByteField("status", None), 

        BitEnumField("saturating_counters", 0, 1, {0 : "no", 1 : "yes"}), 
        BitField("reserved", 0, 3), 
        BitEnumField("power_source", 0, 4, {0 : "line_power", 1 : "battery_power", 2 : "recheargeable_battery_power_or_power_scavenging"}), 
        IEEEFloatField("peak_packets_per_second", None), 
        IntField("duration_at_peak_packet", None), 
        IntField("time_to_recover_from_power_drain", None), 
        SignedByteField("rsl", None), 
        IntField("required_keepalive_time", None), 
        ShortField("max_neighbors", None), 
        ShortField("max_packet_buffers", None)        

    ]



class WirelessHart_Read_Wireless_Module_Revision_Request(WirelessHart_Command_Payload):
    name = "Read Wireless Module Revision Request"
    fields_desc = [

    ]

class WirelessHart_Read_Wireless_Module_Revision_Response(WirelessHart_Command_Payload):
    name = "Read Wireless Module Revision Response"
    fields_desc = [
        ByteField("status", None), 

        XShortEnumField("expanded_device_type", None, EXPANDED_DEVICE_TYPES), 
        XShortEnumField("manufacturer_id_code", None, MANUFACTURERS_ID_CODES), 
        ByteField("device_revision_level", None), 
        ByteField("software_revision_level", None), 
        ByteField("hardware_revision_level", None), 
        
    ]

class WirelessHart_Write_CCA_Mode_Request(WirelessHart_Command_Payload):
    name = "Write CCA Mode Request"
    fields_desc = [
        ByteEnumField("cca_mode", None, { 0 : "disabled", 1 : "energy_detect", 2 : "carrier_sense", 3: "carrier_sense + energy_detect"})
    ]

class WirelessHart_Write_CCA_Mode_Response(WirelessHart_Command_Payload):
    name = "Write CCA Mode Response"
    fields_desc = [
        ByteField("status", None), 
        ByteEnumField("cca_mode", None, { 0 : "disabled", 1 : "energy_detect", 2 : "carrier_sense", 3: "carrier_sense + energy_detect"})
    ]


class WirelessHart_Write_Modify_Route_Request(WirelessHart_Command_Payload):
    name = "Write / Modify Route Request"
    fields_desc = [
        ByteField("route_id", None), 
        XShortField("destination_nickname", None), 
        XShortField("graph_id", None), 

    ]

class WirelessHart_Write_Modify_Route_Response(WirelessHart_Command_Payload):
    name = "Write / Modify Route Response"
    fields_desc = [
        ByteField("status", None),
        ByteField("route_id", None), 
        XShortField("correspondent_nickname", None), 
        XShortField("graph_id", None),
        ByteField("number_of_remaining_routes", None) 

    ]


class WirelessHart_Write_Timer_Interval_Request(WirelessHart_Command_Payload):
    name = "Write Timer Interval Request"
    fields_desc = [
        ByteEnumField("timer_type", None, {
            0 : "discovery", 
            1 : "advertisement", 
            2 : "keepalive", 
            3 : "path_failure", 
            4 : "health_report", 
            5 : "broadcast_reply",
            6 : "max_pdu_age", 
            7 : "max_reply_time"
        }), 
        IntField("timer_interval", None), 
    ]


class WirelessHart_Write_Timer_Interval_Response(WirelessHart_Command_Payload):
    name = "Write Timer Interval Response"
    fields_desc = [
        ByteField("status", None), 
        ByteEnumField("timer_type", None, {
            0 : "discovery", 
            1 : "advertisement", 
            2 : "keepalive", 
            3 : "path_failure", 
            4 : "health_report", 
            5 : "broadcast_reply",
            6 : "max_pdu_age", 
            7 : "max_reply_time"
        }), 
        IntField("timer_interval", None), 
    ]

class WirelessHart_Write_RTC_Time_Mapping_Request(WirelessHart_Command_Payload):
    name = "Write RTC Time Mapping Request"
    fields_desc = [
        ByteField("day_date", None), 
        ByteEnumField("month_date", None, MONTH_TYPE), 
        ByteEnumField("year_date", None, YEAR_TYPE), # -1900 

        IntField("time", None), 
    ]

class WirelessHart_Write_RTC_Time_Mapping_Response(WirelessHart_Command_Payload):
    name = "Write RTC Time Mapping Response"
    fields_desc = [
        ByteField("status", None), 

        ByteField("day_date", None), 
        ByteEnumField("month_date", None, MONTH_TYPE), 
        ByteEnumField("year_date", None, YEAR_TYPE), # -1900 

        IntField("time", None), 
    ]


class WirelessHart_Read_Packet_TTL_Request(WirelessHart_Command_Payload):
    name = "Read Packet Time To Live (TTL) Request"
    fields_desc = [
    ]

class WirelessHart_Read_Packet_TTL_Response(WirelessHart_Command_Payload):
    name = "Read Packet Time To Live (TTL) Response"
    fields_desc = [
        ByteField("status", None), 
        ByteField("ttl", None)
    ]


class WirelessHart_Write_Timetable_Request(WirelessHart_Command_Payload):
    name = "Request Timetable Request"
    fields_desc = [
        ByteField("timetable_id", None),
        BitField("reserved", 0, 5), 
        BitField("intermittent", 0, 1), 
        BitField("sink", 0, 1), 
        BitField("source", 0, 1), 

        ByteEnumField("timetable_application_domain", None, {0:"publish", 1:"event", 2:"maintenance", 3:"block_transfer"}), 

        XShortField("peer_nickname", None), 
        IntField("period", None),

        ByteField("route_id", None)
    ]


class WirelessHart_Write_Timetable_Response(WirelessHart_Command_Payload):
    name = "Request Timetable Response"
    fields_desc = [
        ByteField("timetable_id", None),
        BitField("reserved", 0, 5), 
        BitField("intermittent", 0, 1), 
        BitField("sink", 0, 1), 
        BitField("source", 0, 1), 

        ByteEnumField("timetable_application_domain", None, {0:"publish", 1:"event", 2:"maintenance", 3:"block_transfer"}), 

        XShortField("peer_nickname", None), 
        IntField("period", None),

        ByteField("route_id", None), 
        
        ByteField("number_of_timetables_remaining", None), 

    ]



class WirelessHart_Request_Timetable_Request(WirelessHart_Command_Payload):
    name = "Request Timetable Request"
    fields_desc = [
        ByteField("timetable_id", None),

        BitField("reserved", 0, 5), 
        BitField("intermittent", 0, 1), 
        BitField("sink", 0, 1), 
        BitField("source", 0, 1), 
        ByteEnumField("timetable_application_domain", None, {0:"publish", 1:"event", 2:"maintenance", 3:"block_transfer"}), 
        XShortField("peer_nickname", None), 
        IntField("period", None)
    ]

class WirelessHart_Request_Timetable_Response(WirelessHart_Command_Payload):
    name = "Request Timetable Response"
    fields_desc = [
        ByteField("status", None), 

        ByteField("timetable_id", None),

        BitField("reserved", 0, 5), 
        BitField("intermittent", 0, 1), 
        BitField("sink", 0, 1), 
        BitField("source", 0, 1), 
        ByteEnumField("timetable_application_domain", None, {0:"publish", 1:"event", 2:"maintenance", 3:"block_transfer"}), 
        XShortField("peer_nickname", None), 
        IntField("period", None),
        ByteField("route_id", None)
    ]

class WirelessHart_Read_Unique_Identifier_Request(WirelessHart_Command_Payload):
    name = "Read Unique Identifier Request"
    fields_desc = []


class WirelessHart_Read_Unique_Identifier_Response(WirelessHart_Command_Payload):
    name = "Read Unique Identifier Response"
    fields_desc = [
        ByteField("status", None), 
        ByteField("static", 254), 
        XShortEnumField("expanded_device_type", None, EXPANDED_DEVICE_TYPES), 
        ByteField("min_preambles", None), 
        ByteField("protocol_major_revision", None), 
        ByteField("device_revision_level", None), 
        ByteField("software_revision_level", None), 
        BitField("hardware_revision_level", 0, 5), 

        BitEnumField("physical_signaling_code", 0, 3, {
            0 : "bell_202_current", 
            1 : "bell_202_voltage", 
            2 : "rs_485", 
            3 : "rs_232", 
            4 : "wireless", 
            6 : "special" 
        }), 

        BitField("c8psk_in_multidrop_only", 0, 1),
        BitField("c8psk_capable_field_device", 0, 1),
        BitField("reserved1", 0, 1),
        BitField("safehart_capable_field_device", 0, 1),
        BitField("dot15d4_oqpsk", 0, 1),
        BitField("protocol_bridge_device", 0, 1),
        BitField("eeprom_control", 0, 1),
        BitField("multisensor_field_device", 0, 1),
        ThreeBytesField("device_id", None), 
        ByteField("preambles_number", None), 
        ByteField("last_device_variable_code", None), 
        ShortField("configuration_change_counter", None), 


        # Extended Device status byte
        BitField('reserved2', 0, 2), 
        BitEnumField('function_check', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('out_of_specification', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('failure', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('critical_power_failure', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('device_variable_alert', 0, 1, {0 : "no", 1: "yes"}), 
        BitEnumField('maintenance_required', 0, 1, {0 : "no", 1: "yes"}), 

    ]
    

class WirelessHart_Report_Device_Health_Request(WirelessHart_Command_Payload):
    name = "Report Device Health Request"
    fields_desc = []

class WirelessHart_Report_Device_Health_Response(WirelessHart_Command_Payload):
    name = "Report Device Health Response"
    fields_desc = [
        ByteField("status", None), 
        ShortField("generated_packets", None), 
        ShortField("terminated_packets", None),
        ShortField("datalink_mic_failures", None),
        ShortField("network_mic_failures", None), 
        ByteEnumField("power_status", None, {
            0 : "nominal", 
            1 : "low", 
            2 : "critically_low", 
            3 : "recharging_low", 
            4 : "recharging_high"
        }),
        ByteField("crc_failures", None), 
        ByteField("unicast_nonce_counter_values_not_received", None), 
        ByteField("max_packet_buffer_queue_length", None), 
        IEEEFloatField("average_packet_buffer_queue_length", None), 

        IntField("average_latency_packets_from_gateway", None), 
        IntField("variance_latency_packets_from_gateway", None),
        IntField("timely_packets_received", None), 
        IntField("late_packets_received", None), 
        ByteField("unknown_sessions_received", None)


    ]


class WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request(WirelessHart_Command_Payload):
    name = "Vendor Specific (Dust Networks) Ping Request"
    fields_desc = [
        XShortField("expanded_device_type", None), 
        ShortField("hops", None), 
    ]


class WirelessHart_Vendor_Specific_Dust_Networks_Ping_Response(WirelessHart_Command_Payload):
    name = "Vendor Specific (Dust Networks) Ping Response"
    fields_desc = [
        ByteField("status", None), 
        XShortField("expanded_device_type", None), 
        ShortField("hops", None),
        ShortField("temperature", None), # / 10 -> val en deg celcius
        ShortField("voltage", None), # / 100 -> val en V

    ]

bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_DataLink_Acknowledgement, pdu_type=0)
bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_DataLink_Advertisement, pdu_type=1)
bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_DataLink_KeepAlive, pdu_type=2)
bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_Network_Hdr, pdu_type=7)

bind_layers(WirelessHart_Network_Hdr, WirelessHart_Network_Security_SubLayer_Hdr)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Report_Device_Health_Request, command_number=0x30b)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Report_Device_Health_Response, command_number=0x30b)
#bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Read_Unique_Identifier_Request, command_number=0x0)
#bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Read_Unique_Identifier_Response, command_number=0x0)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Report_Neighbor_Signal_Level_Command_Request, command_number=0x313)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Report_Neighbor_Signal_Level_Command_Response, command_number=0x313)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_Network_Key_Request, command_number=0x3c1) # 961: broadcast network key
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_Network_Key_Response, command_number=0x3c1) # 961: broadcast network key

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_Device_Nickname_Request, command_number=0x3c2)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_Device_Nickname_Response, command_number=0x3c2)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_Modify_Session_Command_Request, command_number=0x3c3) # 963 : unicast network key
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_Modify_Session_Command_Response, command_number=0x3c3) # 963 : unicast network key

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_Modify_Superframe_Request, command_number=0x3c5) # 965 : write/modify superframe info
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_Modify_Superframe_Response, command_number=0x3c5) # 965 : write/modify superframe info

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Add_Link_Request, command_number=0x3c7) # 967 : add link
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Add_Link_Response, command_number=0x3c7) # 967 : add link

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_Neighbor_Property_Flag_Request, command_number=0x3cb)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_Neighbor_Property_Flag_Response, command_number=0x3cb)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Read_Wireless_Device_Capabilities_Request, command_number=0x309)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Read_Wireless_Device_Capabilities_Response, command_number=0x309)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Read_Wireless_Module_Revision_Request, command_number=0xfc00)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Read_Wireless_Module_Revision_Response, command_number=0xfc00)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_CCA_Mode_Request, command_number=0x325)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_CCA_Mode_Response, command_number=0x325)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_Modify_Route_Request, command_number=0x3ce)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_Modify_Route_Response, command_number=0x3ce)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_Timer_Interval_Request, command_number=0x31b)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_Timer_Interval_Response, command_number=0x31b)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_RTC_Time_Mapping_Request, command_number=0x319)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_RTC_Time_Mapping_Response, command_number=0x319)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Read_Packet_TTL_Request, command_number=0x328)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Read_Packet_TTL_Response, command_number=0x328)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Request_Timetable_Request, command_number=0x31f)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Request_Timetable_Response, command_number=0x31f)

bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Write_Timetable_Request, command_number=0x3cd)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Write_Timetable_Response, command_number=0x3cd)


bind_layers(WirelessHart_Command_Request_Hdr, WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request, command_number=0xfc04)
bind_layers(WirelessHart_Command_Response_Hdr, WirelessHart_Vendor_Specific_Dust_Networks_Ping_Response, command_number=0xfc05)

old_guess_payload_class = Dot15d4Data.guess_payload_class

def new_guess_payload_class(self, payload):
    if conf.dot15d4_protocol == "wirelesshart":
        return WirelessHart_DataLink_Hdr
    else:
        return old_guess_payload_class(self, payload)

Dot15d4Data.guess_payload_class = new_guess_payload_class

from Cryptodome.Cipher import AES
from copy import copy

conf.dot15d4_protocol = "wirelesshart"

def compute_dlmic(pkt, key):
    data = bytes(pkt)[:-6]
    nonce  = pack('>Q', pkt.asn if hasattr(pkt, "asn") else pkt.asn_snippet)[-5:] + pack('>Q', pkt.src_addr)

    print("data:", bytes(pkt).hex())
    print("data:", data.hex())
    print("nonce:", nonce.hex())
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(data) # not encrypted but authenticated : full DLPDU (from 0x41 to the end of payload - just before MIC and empty encryption data)
    X1= cipher.encrypt(b"")
    tag = cipher.digest()
    return tag

def decrypt_nwk(pkt, key):
    mic = pack(">I", pkt.nwk_mic)
    
    encrypted_pkt = copy(pkt)
    encrypted_pkt.counter = 0
    encrypted_pkt.ttl = 0
    encrypted_pkt.nwk_mic = 0
    
    auth = bytes(encrypted_pkt[WirelessHart_Network_Hdr])
    encrypted_payload = bytes(encrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr][1:])
    auth = auth[:len(auth) - len(encrypted_payload)]
    
    try:
        if pkt.security_types == 1:
            if pkt.nwk_src_addr == 0xf980:
                addr = pkt.nwk_dest_addr
                start_byte = b"\x01"
            else:
                addr = pkt.nwk_src_addr
                start_byte = b"\x00"
            nonce = start_byte + pack('>I', pkt.counter) + pack('>Q', addr)
        else:

            addr = pkt.nwk_src_addr
            start_byte = b"\x00"
            #addr = pkt.nwk_src_addr
            #start_byte = b"\x00"
            nonce = start_byte + pack('>I', pkt.counter) + pack('>Q', addr)

        '''
        print("[i] Decryption (NWK)")
        print("    * key  : ", key.hex())
        print("    * data : ", encrypted_payload.hex())
        print("    * auth : ", auth.hex())
        print("    * nonce: ", nonce.hex())
        '''
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(auth)
        decrypted = cipher.decrypt_and_verify(encrypted_payload, received_mac_tag=mic)

        print("[i] Decryption success ! ({})".format(key.hex()))
        print("    * decr:  ", decrypted.hex())
        print()
        return decrypted
    
    except ValueError:
        #print("[e] Decryption failure - incorrect MIC (recv:", mic.hex(), ")")
        #print(  repr(pkt))
        return None
        
key_found = False
#unicast_session_key     = bytes.fromhex("e06a7fa7f38a405bd2ff238d23dcdc1c")
#broadcast_session_key   = bytes.fromhex("5ac873bfa618d4ce181d6f5faeabfb3b")

unicast_session_key = []
broadcast_session_key = []

assigned_nickname = 0x0002
if __name__ == "__main__":
    count = 0
    pkts = rdpcap("whad/ressources/pcaps/wireless_hart_capture_channel_11_41424344414243444142434441424344_2nodes.pcap")
    for pkt in pkts:
        dot15d4_bytes = bytes(pkt)[44:]
        dot15d4_pkt = Dot15d4FCS(dot15d4_bytes)
        if WirelessHart_DataLink_Advertisement not in dot15d4_pkt:
            
            if WirelessHart_Network_Security_SubLayer_Hdr in dot15d4_pkt and dot15d4_pkt.security_types == 1:
                decrypted = decrypt_nwk(dot15d4_pkt, key=b"ABCDABCDABCDABCD")
                
                if decrypted is not None:
                    for c in WirelessHart_Transport_Layer_Hdr(decrypted).commands:
                        if hasattr(c, "key_value"):
                            if c.key_value not in unicast_session_key:
                                print(repr(c))
                                print("KEY", c.key_value.hex())
                                unicast_session_key.append(c.key_value)
                        '''
                        if WirelessHart_Write_Modify_Session_Command_Request in c and hasattr(c, "key_value"):
                            unicast_session_key.append(c.key_value)
                            unicast_session_key = list(set(unicast_session_key))
                            print("[i] found unicast key:",c.key_value.hex())
                        elif WirelessHart_Write_Network_Key_Request in c and hasattr(c, "key_value"):
                            broadcast_session_key.append(c.key_value)
                            broadcast_session_key = list(set(broadcast_session_key))
                            print("[i] found broadcast key:",c.key_value.hex())
                        elif WirelessHart_Write_Modify_Session_Command_Response in c and hasattr(c, "key_value"):
                            unicast_session_key.append(c.key_value)
                            unicast_session_key = list(set(unicast_session_key))
                            print("[i] found unicast key:",c.key_value.hex())
                        elif WirelessHart_Write_Network_Key_Response in c and hasattr(c, "key_value"):
                            broadcast_session_key.append(c.key_value)
                            broadcast_session_key = list(set(broadcast_session_key))
                            print("[i] found broadcast key:",c.key_value.hex())
                        '''
                            #key_found = True
                            # e06a7fa7f38a405bd2ff238d23dcdc1c
                            # 5ac873bfa618d4ce181d6f5faeabfb3b

                    #WirelessHart_Transport_Layer_Hdr(decrypted).show()

            elif WirelessHart_Network_Security_SubLayer_Hdr in dot15d4_pkt and dot15d4_pkt.security_types == 0:
                print(hex(dot15d4_pkt.nwk_src_addr), "->", hex(dot15d4_pkt.nwk_dest_addr))
                if len(unicast_session_key) > 0:
                    dec = None
                    for k in unicast_session_key:
                        #print("[i] Trying key ", k.hex())
                        decrypted = decrypt_nwk(dot15d4_pkt, key=k)
                        if decrypted is not None:
                            for c in WirelessHart_Transport_Layer_Hdr(decrypted).commands:
                                if hasattr(c, "key_value"):
                                    if c.key_value not in unicast_session_key:
                                        print(repr(c))
                                        print("KEY", c.key_value.hex())
                                        unicast_session_key.append(c.key_value)

                            dec = WirelessHart_Transport_Layer_Hdr(decrypted)
                            break
                    if dec is None:
                        print("FAIL: ", repr(dot15d4_pkt))
                    else:
                        print("WIN: ", repr(dot15d4_pkt))
                        dec.show()
                    #dot15d4_pkt.show()
                    
                    # Not working for now...
                    #print("received mic:", hex(dot15d4_pkt.mic))
                    #print("computed mic:", compute_dlmic(dot15d4_pkt,broadcast_session_key[::-1]).hex())


                    #break
                    #dot15d4_pkt.show()
                    #decrypted = decrypt_nwk(dot15d4_pkt, key=unicast_session_key)#[::-1])
                    #if decrypted is not None:
                    #    print("[!] success", decrypted)
                    #else:
                    #    print("[!] failure")
                    #    break
        else:
            #print("ASN", hex(dot15d4_pkt.asn))
            pass#dot15d4_pkt.show()
            #print("received mic:", hex(dot15d4_pkt.mic))
            #print("computed mic:", compute_dlmic(dot15d4_pkt, b'www.hartcomm.org').hex())
            #break
print(unicast_session_key)
'''
conf.dot15d4_protocol = "wirelesshart"


pkts = rdpcap("whad/ressources/pcaps/wireless_hart_capture_channel_11_41424344414243444142434441424344.pcapng")
for pkt in pkts:
    dot15d4_bytes = bytes(pkt)[44:]
    dot15d4_pkt = Dot15d4FCS(dot15d4_bytes)
    if WirelessHart_DataLink_Advertisement not in dot15d4_pkt:
        dot15d4_pkt.show()
        print(dot15d4_bytes.hex())
        print(bytes(dot15d4_pkt).hex())
'''    
'''       
from Cryptodome.Cipher import AES
    
# good crypto !
# non encrypted payload, AES-CCM*

data = bytes.fromhex("4188e0cd04ffff01003100000204e0110fff7f000003000400010042420101000100530404008006000e4a00154a00174a004b4a00524a006e4a")

print(data)
nonce  = bytes.fromhex("00000204e0") + 6*b"\x00"+ bytes.fromhex("0001")

cipher = AES.new(b'www.hartcomm.org', AES.MODE_CCM, nonce=nonce, mac_len=4)
cipher.update(data) # not encrypted but authenticated : full DLPDU (from 0x41 to the end of payload - just before MIC and empty encryption data)
X1= cipher.encrypt(b"")
tag = cipher.digest()
print(X1.hex(), tag.hex())
'''