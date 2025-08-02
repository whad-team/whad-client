"""
Write procedure
"""
from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Handle_Value_Indication, ATT_Handle_Value_Notification, ATT_Write_Request, ATT_Write_Response, ATT_Hdr

from .attribute import Characteristic, ClientCharacteristicConfigurationDescriptor, find_attr_by_handle, find_charac_by_desc_handle
from .procedure import Procedure, UnexpectedProcError

class ServerWriteProcedure(Procedure):
    """ATT server Write procedure."""

    OPCODE = 0x12

    STATE_INDICATION_SENT = Procedure.STATE_USER

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ServerWrite procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Write_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on WriteRequest."""
        if ATT_Write_Request not in request and self.get_state() == Procedure.STATE_INITIAL:
            self.set_state(Procedure.STATE_ERROR)
            raise UnexpectedProcError()
        # If we receive a confirmation then indication has correctly been sent.
        elif ATT_Hdr in request and request[ATT_Hdr].opcode == 0x1e and self.get_state() == self.STATE_INDICATION_SENT:
            self.set_state(Procedure.STATE_DONE)
            return []

        request = request[ATT_Write_Request]

        # Search for the requested attribute
        try:
            attr = find_attr_by_handle(self.attributes, request.gatt_handle)

            # Find parent characteristic
            charac = find_charac_by_desc_handle(self.attributes, request.gatt_handle)
            if charac is None:
                self.set_state(Procedure.STATE_DONE)
                return [ ATT_Write_Response() ]

            # Make sure the characteristic has the notification or indication bit set
            if request.data == b"\x01\x00" and not charac.has_property(Characteristic.PROP_NOTIFY):
                return self.att_error_response(request.gatt_handle, Procedure.ERR_VALUE_NOT_ALLOWED)
            if request.data == b"\x02\x00" and not charac.has_property(Characteristic.PROP_INDICATE):
                return self.att_error_response(request.gatt_handle, Procedure.ERR_VALUE_NOT_ALLOWED)

            # Check we are attempting to modify a characteristic value or a CCCD
            if attr.writeable():
                attr.value = request.data
                # If we are writing into a CCCD, we must send a notification/indication immediately after, and
                # wait for a confirmation if required.
                if isinstance(attr, ClientCharacteristicConfigurationDescriptor):

                    # Check if we enabled notification or indication
                    if attr.value[0] == 0x01:
                        # We must find the parent characteristic and send a notification
                        notification = ATT_Handle_Value_Notification(gatt_handle=charac.value_handle, value=b"Notified")
                        self.set_state(Procedure.STATE_DONE)
                        return [ ATT_Write_Response(), notification ]
                    elif attr.value[0] == 0x02:
                        # Find the parent characteristic and send an indication
                        indication = ATT_Handle_Value_Indication(gatt_handle=charac.value_handle, value=b"Indicated")
                        self.set_state(self.STATE_INDICATION_SENT)
                        return [ ATT_Write_Response(), indication ]
                    else:
                        self.set_state(Procedure.STATE_DONE)
                        return [ ATT_Write_Response() ]
                else:
                    self.set_state(Procedure.STATE_DONE)
                    return [ ATT_Write_Response() ]
            else:
                self.set_state(Procedure.STATE_DONE)
                return self.att_error_response(request.gatt_handle, Procedure.ERR_WRITE_NOT_PERMITTED)
        except IndexError:
            self.set_state(Procedure.STATE_DONE)
            return self.att_error_response(request.gatt_handle, Procedure.ERR_ATTR_NOT_FOUND)

