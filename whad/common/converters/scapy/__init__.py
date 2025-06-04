"""
This module provides common converters for different data formats.
"""
from json import dumps
from dataclasses import fields

# Scapy
from scapy.packet import Packet
from scapy.fields import PacketListField, FlagValue

# WHAD
from whad.hub.metadata import Metadata

class ScapyConverter:
    """
    This class provides a basic API to convert a scapy packet to different
    representations and vice versa.
    """
    @classmethod
    def get_dict_from_scapy_packet(cls, pkt: Packet) -> dict:
        """
        This function converts a scapy packet to a python dictionary including
        the different layers and fields of the packet.

        :param pkt: packet to convert
        :type pkt: Packet
        :return: Packet converted into a dict
        :rtype: dict
        """

        pkt_dict = {}

        # Parsing of metadata structure
        if hasattr(pkt, "metadata"):
            pkt_dict["metadata"] = {}
            # We iterate over fields of the selected metadata class and
            # populate a sub dictionary linked to "metadata" key
            for field in fields(Metadata) + fields(pkt.metadata.__class__):
                try:
                    value = getattr(pkt.metadata, field.name)
                    # Add attributes if they are only defined
                    if value is not None:
                        if isinstance(value, (int, float)):
                            pkt_dict["metadata"][field.name] = value
                        else:
                            pkt_dict["metadata"][field.name] = str(value)
                except AttributeError:
                    pass

        # Iterate of each layer of the scapy packet
        for layer in pkt.layers():
            current_layer = {}
            # For a given layer, iterate over the fields of the scapy packet
            for field in layer.fields_desc:

                # In the case of a packet list field, call recursively the method to
                # process the sub-packets
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

        # Return packet as a dict
        return pkt_dict

    @classmethod
    def get_json_from_scapy_packet(cls, pkt: Packet) -> str:
        """
        This function converts a scapy packet to JSON including the different
        layers and fields of the packet.

        :param pkt: packet to convert
        :type pkt: Packet
        """
        return dumps(cls.get_dict_from_scapy_packet(pkt))
