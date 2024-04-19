"""WHAD Protocol BLE address messages abstraction layer.
"""

from ..message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper
from . import BleDomain

@pb_bind(BleDomain, 'set_bd_addr', 1)
class SetBdAddress(PbMessageWrapper):
    """Device info query message class
    """

    bd_address = PbFieldBytes('ble.set_bd_addr.bd_address')
    addr_type = PbFieldInt('ble.set_bd_addr.addr_type')
