"""WHAD Protocol Dot15d4 address messages abstraction layer.
"""

from ..message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper
from . import Dot15d4Domain

@pb_bind(Dot15d4Domain, 'set_node_addr', 1)
class SetNodeAddress(PbMessageWrapper):
    """Device info query message class
    """

    address = PbFieldBytes('dot15d4.set_node_addr.address')
    addr_type = PbFieldInt('dot15d4.set_node_addr.address_type')
