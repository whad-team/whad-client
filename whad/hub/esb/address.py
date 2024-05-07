"""WHAD Protocol ESB address messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
#from whad.protocol.esb.esb_pb2 import GetSupportedFrequenciesCmd
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldArray, PbMessageWrapper
from . import EsbDomain

@pb_bind(EsbDomain, 'set_node_addr', 1)
class SetNodeAddress(PbMessageWrapper):
    """ESB SetNodeAddress message
    """

    address = PbFieldBytes('esb.set_node_addr.address')
