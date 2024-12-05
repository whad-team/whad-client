"""
BTMesh Reassemble Fragments
============================

Module provides class to reassemble fragmented packets. No crypto here.
"""

from typing import List
from functools import reduce
from scapy.packet import Packet
from whad.scapy.layers.btmesh import (
    BTMesh_Generic_Provisioning_Transaction_Start,
    BTMesh_Generic_Provisioning_Transaction_Continuation,
    BTMesh_Provisioning_Hdr,
)


class GenericFragmentsAssembler(object):
    """docstring for GenericFragmentsAssembler."""

    pkts: List[Packet] = []

    def __init__(self, fragments=[]):
        super(GenericFragmentsAssembler, self).__init__()
        self.fragments = fragments

    def add_next_fragment(self, fragment):
        """
        Add next packet of transaction (considered in order)

        :param pkt: Packet to add
        :type pkt: Packet
        """
        self.fragments.append(fragment)

    def reassemble(self):
        if len(self.fragments) < 1:
            return None
        elif len(self.fragments) == 1:
            return self.fragments[0]

        return self.reassemble_generic_provisioning()

    def _get_generic_provisioning_fragment(self, pkt):
        """
        Extract the fragment from the Generic Provisioning Layer

        :param pkt: Packet in question
        :type pkt: Packet
        """
        trans_start = pkt.getlayer(BTMesh_Generic_Provisioning_Transaction_Start)
        if trans_start is not None:
            return bytes(trans_start.payload)

        trans_continuation = pkt.getlayer(
            BTMesh_Generic_Provisioning_Transaction_Continuation
        )
        if trans_continuation is not None:
            return bytes(trans_continuation.generic_provisioning_payload_fragment)

    def reassemble_generic_provisioning(self):
        """
        Reassemble fragment contained in Generic Provisioning Transaction. Can only encapsulate BTMesh_Provisioning_Hdr PDU
        """

        reassembled_payload = reduce(
            lambda res, pkt: res + self._get_generic_provisioning_fragment(pkt),
            self.pkts, b""
        )
        return BTMesh_Provisioning_Hdr(reassembled_payload)
