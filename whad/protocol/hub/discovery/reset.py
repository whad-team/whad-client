"""WHAD Protocol Discovery reset messages abstraction layer.
"""

from whad.protocol.whad_pb2 import Message
from whad.protocol.device_pb2 import DeviceResetQuery, DeviceReadyResp
from whad.protocol.hub import pb_bind, PbMessageWrapper
from whad.protocol.hub.discovery import Discovery

@pb_bind(Discovery, 'reset_query', 1)
class ResetQuery(PbMessageWrapper):
    """Device reset message class
    """
    
    def __init__(self, message: Message = None):
        """Define an empty message deriving from DeviceResetQuery.
        """
        super().__init__(message=message)
        self.message.discovery.reset_query.CopyFrom(DeviceResetQuery())

@pb_bind(Discovery, 'ready_resp', 1)
class DeviceReady(PbMessageWrapper):
    """Device ready message class
    """
    
    def __init__(self, message: Message = None):
        """Define an empty message deriving from DeviceReadyResp.
        """
        super().__init__(message=message)
        self.message.discovery.ready_resp.CopyFrom(DeviceReadyResp())