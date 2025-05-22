from json import dumps
from scapy.fields import PacketListField, FlagValue
from dataclasses import dataclass, field, fields
from whad.hub.metadata import Metadata

class ScapyConverter:
    '''
    This class provides a basic API to convert a scapy packet to different representations and vice versa.
    '''
    @classmethod
    def get_dict_from_scapy_packet(cls, pkt):
        '''
        This function converts a scapy packet to a python dictionary including the different layers and fields of the packet.

        :param pkt: packet to convert
        '''
        
        pkt_dict = {}
        # Parsing of metadata structure
        if hasattr(pkt, "metadata"):
            pkt_dict["metadata"] = {}
            # Here we iterate over fields of the selected metadata class and populates a sub dictionary linked to "metadata" key
            for field in fields(Metadata) + fields(pkt.metadata.__class__):
                if hasattr(pkt.metadata, field.name) and getattr(pkt.metadata,field.name) is not None:
                    if isinstance(getattr(pkt.metadata, field.name), int) or isinstance(getattr(pkt.metadata, field.name), float):
                        pkt_dict["metadata"][field.name] = getattr(pkt.metadata, field.name)
                    else:
                        pkt_dict["metadata"][field.name] = str(getattr(pkt.metadata, field.name))
        # Iterate of each layer of the scapy packet
        for layer in pkt.layers():
            current_layer = {}
            # For a given layer, iterate over the fields of the scapy packet
            for field in layer.fields_desc:

                # In the case of a packet list field, call recursively the method to process the sub-packets
                if isinstance(field, PacketListField) and field.cls is not None:
                    current_layer_list = []
                    for l in getattr(pkt[layer], field.name):
                        current_layer_list.append(cls.get_dict_from_scapy_packet(l))

                    # update the current layer with a list of sub-packets parsed as dict
                    current_layer[field.name] = current_layer_list
                else:
                    # General case, store the field name and its value in the dictionary
                    value = getattr(pkt[layer], field.name)

                    # Special processing for flags
                    if isinstance(value, FlagValue):
                        value = str(value)

                    # Special processing for bytes
                    elif isinstance(value,bytes):
                        value = value.hex()

                    current_layer[field.name] = value
            # update the dict with the current layer parsed as dict
            pkt_dict[layer.__name__] = current_layer

        return pkt_dict

    @classmethod
    def get_json_from_scapy_packet(cls, pkt):
        '''
        This function converts a scapy packet to JSON including the different layers and fields of the packet.

        :param pkt: packet to convert
        '''
        return dumps(cls.get_dict_from_scapy_packet(pkt))
