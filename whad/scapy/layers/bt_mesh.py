from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import ByteEnumField, ShortEnumField, IntField, XShortField, \
    UUIDField, StrFixedLenField, ConditionalField, PacketField, XLongField, XIntField, \
    BitEnumField, BitField
from scapy.layers.bluetooth import EIR_Element, EIR_Hdr, EIR_Raw




class BTMesh_Unprovisioned_Device_Beacon(Packet):
    name = "Bluetooth Mesh Unprovisioned Device Beacon"
    fields_desc = [
        UUIDField("device_uuid", None, uuid_fmt=UUIDField.FORMAT_BE),
        ShortEnumField("oob_information", None, {
            0:"Other",
            1:"Electronic / URI",
            2:"2D machine-readable code",
            3:"Bar code",
            4:"Near Field Communication (NFC)",
            5:"Number",
            6:"String",
            7:"Support for certificate-based provisioning",
            8:"Support for provisioning records",
            9:"Reserved for Future Use",
            10:"Reserved for Future Use",
            11:"On box",
            12:"Inside box",
            13:"On piece of paper",
            14:"Inside manual",
            15:"On device",
        } ),
        IntField("uri_hash", None)
    ]
class BTMesh_Secure_Network_Beacon(Packet):
    name = "Bluetooth Mesh Secure Network Beacon"
    fields_desc = [
        BitEnumField("key_refresh_flag", 0,1,[False, True]),
        BitEnumField("iv_update_flag", 0,1,["normal_operation", "iv_update_in_progress"]),
        BitField("unused", 0,6),
        XLongField("network_id", None),
        XIntField("iv_index", None),
        XLongField("authentication_value", None)

    ]

class BTMesh_Private_Beacon(Packet):
    name = "Bluetooth Mesh Private Beacon"
    fields_desc = [
        StrFixedLenField('random', None, length=13),
        StrFixedLenField('obfuscated_private_beacon_data', None, length=5),
        XLongField("authentication_tag", None)

    ]
class EIR_BTMesh_Beacon(EIR_Element):
    name = "Bluetooth Mesh Beacon"
    fields_desc = [
        ByteEnumField("mesh_beacon_type", None, {
            0x00 : "unprovisioned_device_beacon",
            0x01 : "secure_network_beacon",
            0x02 : "mesh_private_beacon"
        }),
        ConditionalField(
            PacketField("unprovisioned_device_beacon_data", None, pkt_cls=BTMesh_Unprovisioned_Device_Beacon)
        , lambda pkt:pkt.mesh_beacon_type == 0),
        ConditionalField(
            PacketField("secure_beacon_data", None, pkt_cls=BTMesh_Secure_Network_Beacon)
        , lambda pkt:pkt.mesh_beacon_type == 1),
        ConditionalField(
            PacketField("private_beacon_data", None, pkt_cls=BTMesh_Private_Beacon)
        , lambda pkt:pkt.mesh_beacon_type == 2)
    ]

split_layers(EIR_Hdr, EIR_Raw)
bind_layers(EIR_Hdr, EIR_BTMesh_Beacon, type=0x2b)
bind_layers(EIR_Hdr, EIR_Raw)
