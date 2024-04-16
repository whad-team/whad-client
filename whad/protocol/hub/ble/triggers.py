"""WHAD Protocol BLE prepared sequences messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import ManualTrigger
from whad.protocol.hub import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool, PbFieldArray
from whad.protocol.hub.ble import BleDomain

@pb_bind(BleDomain, "prepare_manual", 1)
class PrepareSequenceManual(PbMessageWrapper):
    """BLE prepare sequence with manual trigger message class
    """

    sequence_id = PbFieldInt("ble.prepare.id")
    direction = PbFieldInt("ble.prepare.direction")
    direction = PbFieldInt("ble.prepare.direction")
    packets = PbFieldArray("ble.prepare.sequence")

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.ble.prepare.trigger.manual.CopyFrom(ManualTrigger())

@pb_bind(BleDomain, "prepare_connevt", 1)
class PrepareSequenceConnEvt(PbMessageWrapper):
    """BLE prepare sequence with connection event trigger message class
    """
    sequence_id = PbFieldInt("ble.prepare.id")
    direction = PbFieldInt("ble.prepare.direction")
    direction = PbFieldInt("ble.prepare.direction")
    packets = PbFieldArray("ble.prepare.sequence")
    connection_event = PbFieldInt("ble.prepare.trigger.connection_event.connection_event")

@pb_bind(BleDomain, "prepare_pattern", 1)
class PrepareSequencePattern(PbMessageWrapper):
    """BLE prepare sequence with reception pattern trigger message class
    """
    sequence_id = PbFieldInt("ble.prepare.id")
    direction = PbFieldInt("ble.prepare.direction")
    direction = PbFieldInt("ble.prepare.direction")
    packets = PbFieldArray("ble.prepare.sequence")
    pattern = PbFieldBytes("ble.prepare.trigger.reception.pattern")
    mask = PbFieldBytes("ble.prepare.trigger.reception.mask")
    offset = PbFieldInt("ble.prepare.trigger.reception.offset")

@pb_bind(BleDomain, "triggered", 1)
class Triggered(PbMessageWrapper):
    """BLE prepare sequence triggered message class
    """
    sequence_id = PbFieldInt("ble.triggered.id")
