"""
BLE ATT layer manager

This layer manager mostly translates Scapy ATT packets into GATT messages required by the GATT
layer, and exposes an interface to the GATT layer in order to allow ATT packets to be forged
and sent to the underlying layer (L2CAP).
"""
import logging

from typing import List
from scapy.layers.bluetooth import ATT_Error_Response, ATT_Exchange_MTU_Request, \
    ATT_Exchange_MTU_Response, ATT_Execute_Write_Request, ATT_Execute_Write_Response, \
    ATT_Find_By_Type_Value_Request, ATT_Find_By_Type_Value_Response, ATT_Find_Information_Request, \
    ATT_Find_Information_Response, ATT_Prepare_Write_Request, ATT_Prepare_Write_Response, \
    ATT_Read_Blob_Request, ATT_Handle_Value_Indication, ATT_Handle_Value_Notification, \
    ATT_Read_Blob_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response, \
    ATT_Read_By_Type_Request, ATT_Read_By_Type_Response, ATT_Read_Multiple_Request, \
    ATT_Read_Multiple_Response, ATT_Read_Request, ATT_Read_Response, ATT_Write_Command, \
    ATT_Write_Response, ATT_Write_Request, ATT_Read_By_Type_Request_128bit, ATT_Hdr, \
    ATT_Handle
from scapy.packet import bind_layers, Packet

from whad.ble.stack.att.constants import BleAttOpcode, SecurityProperty, SecurityAccess

from whad.common.stack import Layer, ContextualLayer, alias, instance

#from whad.ble.stack.gatt import  Gatt
from whad.ble.stack.gatt.message import GattExecuteWriteRequest, GattExecuteWriteResponse, \
    GattFindInfoResponse, GattHandleValueIndication, GattHandleValueNotification, \
    GattPrepareWriteRequest, GattPrepareWriteResponse, GattReadByGroupTypeResponse, \
    GattErrorResponse, GattFindByTypeValueRequest, GattFindByTypeValueResponse, \
    GattFindInfoRequest, GattReadByTypeResponse, GattReadRequest, GattReadResponse, \
    GattReadBlobRequest, GattReadBlobResponse, GattReadMultipleRequest, \
    GattReadMultipleResponse, GattWriteCommand, GattWriteRequest, GattWriteResponse, \
    GattReadByGroupTypeRequest, GattReadByTypeRequest, GattReadByTypeRequest128, \
    GattExchangeMtuResponse, GattExchangeMtuRequest
from whad.scapy.layers.bluetooth import ATT_Handle_Value_Confirmation

logger = logging.getLogger(__name__)


@alias('att')
class ATTLayer(Layer):
    """ATT layer implementation.
    """

    def configure(self, options=None):
        """Layer configuration
        """
        # Initialize state
        self.state.client_att_mtu = 23
        self.state.server_att_mtu = 23

    def set_client_mtu(self, mtu: int):
        """Set ATT client MTU
        """
        if mtu >= 23:
            self.state.client_att_mtu = mtu
    
    def get_client_mtu(self) -> int:
        """Retrieve ATT client MTU
        """
        return self.state.client_att_mtu

    def set_server_mtu(self, mtu: int):
        """Set ATT server MTU
        """
        if mtu >= 23:
            self.state.server_att_mtu = mtu

    def get_server_mtu(self) -> int:
        """Retrieve ATT server MTU
        """
        return self.state.server_att_mtu
    
    def notify_client_mtu(self):
        """Notify l2cap that ATT MTU has changed for client
        """
        self.send("l2cap", self.state.client_att_mtu, tag="ATT_MTU")

    def notify_server_mtu(self):
        """Notify l2cap that ATT MTU has changed for server
        """
        self.send("l2cap", self.state.server_att_mtu, tag="ATT_MTU")

    ##########################################
    # Incoming requests and responses
    ##########################################

    @instance('l2cap')
    def on_packet(self, inst: ContextualLayer, att_pkt: Packet):
        """Dispatch ATT packet.

        :param inst: L2CAP instance object
        :type inst: ContextualLayer
        :param att_pkt: Incoming ATT packet to process
        :type att_pkt: Packet
        """
        if ATT_Error_Response in att_pkt:
            self.on_error_response(att_pkt.getlayer(ATT_Error_Response))
        elif ATT_Exchange_MTU_Request in att_pkt:
            self.on_exch_mtu_request(att_pkt.getlayer(ATT_Exchange_MTU_Request))
        elif ATT_Exchange_MTU_Response in att_pkt:
            self.on_exch_mtu_response(att_pkt.getlayer(ATT_Exchange_MTU_Response))

        elif ATT_Find_Information_Request in att_pkt:
            self.on_find_info_request(att_pkt.getlayer(ATT_Find_Information_Request))
        elif ATT_Find_Information_Response in att_pkt:
            self.on_find_info_response(att_pkt.getlayer(ATT_Find_Information_Response))
        elif ATT_Find_By_Type_Value_Request in att_pkt:
            self.on_find_by_type_value_request(att_pkt.getlayer(ATT_Find_By_Type_Value_Request))
        elif ATT_Find_By_Type_Value_Response in att_pkt:
            self.on_find_by_type_value_response(att_pkt.getlayer(ATT_Find_By_Type_Value_Response))
        elif ATT_Read_By_Type_Request in att_pkt:
            self.on_read_by_type_request(att_pkt.getlayer(ATT_Read_By_Type_Request))
        elif ATT_Read_By_Type_Response in att_pkt:
            self.on_read_by_type_response(att_pkt.getlayer(ATT_Read_By_Type_Response))
        elif ATT_Read_By_Group_Type_Request in att_pkt:
            self.on_read_by_group_type_request(att_pkt.getlayer(ATT_Read_By_Group_Type_Request))
        elif ATT_Read_By_Group_Type_Response in att_pkt:
            self.on_read_by_group_type_response(att_pkt.getlayer(ATT_Read_By_Group_Type_Response))
        elif ATT_Read_Request in att_pkt:
            self.on_read_request(att_pkt.getlayer(ATT_Read_Request))
        elif ATT_Read_By_Type_Request_128bit in att_pkt:
            self.on_read_by_type_request_128bit(att_pkt.getlayer(ATT_Read_By_Type_Request_128bit))
        elif ATT_Read_Response in att_pkt:
            self.on_read_response(att_pkt.getlayer(ATT_Read_Response))
        elif ATT_Read_Blob_Request in att_pkt:
            self.on_read_blob_request(att_pkt.getlayer(ATT_Read_Blob_Request))
        elif ATT_Read_Blob_Response in att_pkt:
            self.on_read_blob_response(att_pkt.getlayer(ATT_Read_Blob_Response))
        elif ATT_Read_Multiple_Request in att_pkt:
            self.on_read_multiple_request(att_pkt.getlayer(ATT_Read_Multiple_Request))
        elif ATT_Read_Multiple_Response in att_pkt:
            self.on_read_multiple_response(att_pkt.getlayer(ATT_Read_Multiple_Response))
        elif ATT_Write_Request in att_pkt:
            self.on_write_request(att_pkt.getlayer(ATT_Write_Request))
        elif ATT_Write_Response in att_pkt:
            self.on_write_response(att_pkt.getlayer(ATT_Write_Response))
        elif ATT_Write_Command in att_pkt:
            self.on_write_command(att_pkt.getlayer(ATT_Write_Command))
        elif ATT_Handle_Value_Notification in att_pkt:
            self.on_handle_value_notification(att_pkt.getlayer(ATT_Handle_Value_Notification))
        elif ATT_Handle_Value_Indication in att_pkt:
            self.on_handle_value_indication(att_pkt.getlayer(ATT_Handle_Value_Indication))
        elif ATT_Prepare_Write_Request in att_pkt:
            self.on_prepare_write_request(att_pkt.getlayer(ATT_Prepare_Write_Request))
        elif ATT_Prepare_Write_Response in att_pkt:
            self.on_prepare_write_response(att_pkt.getlayer(ATT_Prepare_Write_Response))
        elif ATT_Execute_Write_Request in att_pkt:
            self.on_execute_write_request(att_pkt.getlayer(ATT_Execute_Write_Request))
        elif ATT_Execute_Write_Response in att_pkt:
            self.on_execute_write_response(att_pkt.getlayer(ATT_Execute_Write_Response))
        # Signed command not supported yet
        # Write Response has no body
        elif att_pkt.opcode == BleAttOpcode.WRITE_RESPONSE:
            self.on_write_response(None)
        # Read Blob Response has no body
        elif att_pkt.opcode == BleAttOpcode.READ_BLOB_RESPONSE:
            self.on_read_blob_response(None)
        # Read Response has no body
        elif att_pkt.opcode == BleAttOpcode.READ_RESPONSE:
            self.on_read_response(None)
        # Execute write request
        elif att_pkt.opcode == BleAttOpcode.EXECUTE_WRITE_RESPONSE:
            self.on_execute_write_response(None)

    def on_error_response(self, error_resp: ATT_Error_Response):
        """Process a generic ATT error response.

        :param error_resp: Error response packet
        :type error_resp: ATT_Error_Response
        """
        # Send a GattErrorResponse message to gatt
        self.send(
            'gatt',
            GattErrorResponse(
                error_resp.request,
                error_resp.handle,
                error_resp.ecode
            ),
            tag='GATT_ERROR_RSP',
        )

    def on_exch_mtu_request(self, mtu_req: ATT_Exchange_MTU_Request):
        """Handle ATT Exchange MTU request, update L2CAP TX MTU and returns
        our MTU.

        :param mtu_req: MTU request
        :type mtu_req: ATT_Exchange_MTU_Request
        """
        logger.debug("[att] got an MTU exchange request (mtu: %d)", mtu_req.mtu)

        # Send back our MTU.
        #self.send_data(ATT_Exchange_MTU_Response(
        #    mtu=mtu_req.mtu
        #))

        self.send("gatt", GattExchangeMtuRequest(mtu=mtu_req.mtu), tag="XCHG_MTU_REQ")

    def on_exch_mtu_response(self, mtu_resp: ATT_Exchange_MTU_Response):
        """Update L2CAP remote MTU based on ATT_Exchange_MTU_Response.

        :param mtu_resp: MTU response
        :type mtu_resp: ATT_Exchange_MTU_Request
        """

        # Forward to GATT
        self.send('gatt', GattExchangeMtuResponse(mtu=mtu_resp.mtu),
                  tag='XCHG_MTU_RESP')


    def on_find_info_request(self, request: ATT_Find_Information_Request):
        """Handle ATT Find Information Request

        :param request: Request
        :type request: ATT_Find_Information_Request
        """
        self.send('gatt', GattFindInfoRequest(
                request.start,
                request.end
            ), tag='FIND_INFO_REQ'
        )

    def on_find_info_response(self, response: ATT_Find_Information_Response):
        """Handle ATT Find Information Response

        :param response: Find information response packet
        :type response: ATT_Find_Information_Response
        """
        handles = b''.join([item.build() for item in response.handles])
        self.send('gatt', GattFindInfoResponse.from_bytes(
                response.format,
                handles
            ), tag='FIND_INFO_RESP',
        )

    def on_find_by_type_value_request(self, request: ATT_Find_By_Type_Value_Request):
        """Handle ATT Find By Type Value request

        :param request: Find by type request
        :type request: ATT_Find_Information_Response
        """
        self.send('gatt', GattFindByTypeValueRequest(
                request.start,
                request.end,
                request.uuid,
                request.data
            )
        )

    def on_find_by_type_value_response(self, response: ATT_Find_By_Type_Value_Response):
        """Handle ATT Find by type value response

        :param response: Find by type value response packet
        :type response: ATT_Find_Information_Response
        """
        handles = b''.join([item.build() for item in response.handles])
        self.send('gatt', GattFindByTypeValueResponse.from_bytes(handles))

    def on_read_by_type_request(self, request: ATT_Read_By_Type_Request):
        """Handle read by type request

        :param request: ReadByType packet
        :type request: ATT_Read_By_Type_Request
        """
        self.send('gatt', GattReadByTypeRequest(
            request.start,
            request.end,
            request.uuid
        ))

    def on_read_by_type_request_128bit(self, request: ATT_Read_By_Type_Request_128bit):
        """Handle ATT Read By Type Request 128-bit UUID

        :param request: ReadByType request with 128-bit UUID
        :type request: ATT_Read_By_Type_Request_128bit
        """
        self.send('gatt',
            request.start,
            request.end,
            request.uuid1,
            request.uuid2
        )

    def on_read_by_type_response(self, response: GattReadByTypeResponse):
        """Handle read by type response

        :param response: ReadByTypeResponse
        :type response: GattReadByTypeResponse
        """
        # Must rebuild handles payload as bytes, since scapy parsed it :(
        handles = b''.join([item.build() for item in response.handles])
        self.send('gatt', GattReadByTypeResponse.from_bytes(
                response.len,
                handles
            )
        )

    def on_read_request(self, request: ATT_Read_Request):
        """Handle ATT Read Request

        :param request: Read request
        :type request: ATT_Read_Request
        """
        self.send('gatt', GattReadRequest(
                request.gatt_handle
            )
        )

    def on_read_response(self, response: ATT_Read_Response):
        """Handle ATT Read Response

        :param response: Read response
        :type response: ATT_Read_Response
        """
        if response is not None:
            self.send('gatt', GattReadResponse(
                    response.value
                )
            )
        else:
            self.send('gatt', GattReadResponse(
                    b''
                )
            )

    def on_read_blob_request(self, request: ATT_Read_Blob_Request):
        """Handle ATT Read Blob Request

        :param request: ReadBlobRequest
        :type request: ATT_Read_Blob_Request
        """
        self.send('gatt', GattReadBlobRequest(
                request.gatt_handle,
                request.offset
            )
        )

    def on_read_blob_response(self, response: ATT_Read_Blob_Response):
        """Handle ATT Read Blob Response

        :param response: ATT response if provided, None otherwise.
        :type response: ATT_Read_Blob_Response
        """
        if response is not None:
            self.send('gatt', GattReadBlobResponse(
                    response.value
                )
            )
        else:
            self.send('gatt', GattReadBlobResponse(
                    None
                )
            )

    def on_read_multiple_request(self, request: ATT_Read_Multiple_Request):
        """Handle ATT Read Multiple Request

        :param request: ReadMultiple request
        :type request: ATT_Read_Multiple_Request
        """
        self.send('gatt',GattReadMultipleRequest(request.handles))

    def on_read_multiple_response(self, response: ATT_Read_Multiple_Response):
        """Handle ATT Read Multiple Response

        :param response: ReadMultiple response
        :type response: ATT_Read_Multiple_Response
        """
        self.send('gatt', GattReadMultipleResponse(response.values))

    def on_read_by_group_type_request(self, request: ATT_Read_By_Group_Type_Request):
        """Handle ATT Read By Group Type Request

        :param request: ReadByGroupType request
        :type request: ATT_Read_By_Group_Type_Request
        """
        self.send('gatt', GattReadByGroupTypeRequest(
                request.start,
                request.end,
                request.uuid
            )
        )

    def on_read_by_group_type_response(self, response: ATT_Read_By_Group_Type_Response):
        """Handle ATT Read By Group Type Response

        :param response: ReadByGroupType response
        :type response: ATT_Read_By_Group_Type_Response
        """
        self.send('gatt', GattReadByGroupTypeResponse.from_bytes(
                response.length,
                response.data
            )
        )

    def on_write_request(self, request: ATT_Write_Request):
        """Handle ATT Write Request

        :param request: Write request
        :type request: ATT_Write_Request
        """
        self.send('gatt', GattWriteRequest(
                request.gatt_handle,
                request.data
            )
        )

    def on_write_response(self, response: ATT_Write_Response):
        """Handle ATT Write Response

        :param response: Write response
        :type response: ATT_Write_Response
        """
        self.send('gatt', GattWriteResponse())

    def on_write_command(self, command: ATT_Write_Command):
        """Handle ATT Write Command

        :param command: Write command
        :type command: ATT_Write_Command
        """
        self.send('gatt', GattWriteCommand(
                command.gatt_handle,
                command.data
            )
        )

    def on_prepare_write_request(self, request:ATT_Prepare_Write_Request):
        """Handle ATT Prepare Write Request

        :param request: PrepareWrite request
        :type request: ATT_Prepare_Write_Request
        """
        self.send('gatt', GattPrepareWriteRequest(
                request.gatt_handle,
                request.offset,
                request.data
            )
        )

    def on_prepare_write_response(self, response: ATT_Prepare_Write_Response):
        """Handle ATT Prepare Write Response

        :param response: PrepareWrite response
        :type response: ATT_Prepare_Write_Response
        """
        self.send('gatt', GattPrepareWriteResponse(
                response.gatt_handle,
                response.offset,
                response.data
            )
        )

    def on_execute_write_request(self, request: ATT_Execute_Write_Request):
        """Handle ATT Execute Write Request

        :param request: ExecuteWrite request
        :type request: ATT_Execute_Write_Request
        """
        self.send('gatt', GattExecuteWriteRequest(
                request.flags
            )
        )

    def on_execute_write_response(self, response: ATT_Execute_Write_Response):
        """Handle ATT Execute Write Response

        :param response: ExecuteWrite response
        :type response: ATT_Execute_Write_Response
        """
        self.send('gatt', GattExecuteWriteResponse())

    def on_handle_value_notification(self, notif: ATT_Handle_Value_Notification):
        """Handle ATT Handle Value Notification

        :param notif: Handle value notification packet
        :type notif: ATT_Handle_Value_Notification
        """
        self.send('gatt', GattHandleValueNotification(
                notif.gatt_handle,
                notif.value
            )
        )

    def on_handle_value_indication(self, notif: ATT_Handle_Value_Indication):
        """Handle ATT Handle Value indication

        :param notif: Handle value indication packet
        :type notif: ATT_Handle_Value_Indication
        """
        self.send('gatt', GattHandleValueIndication(
                notif.gatt_handle,
                notif.value
            )
        )

    ##########################################
    # Outgoing requests and responses
    ##########################################

    def send_data(self, packet: Packet):
        """Send packet to underlying L2CAP layer

        :param packet: Packet to send to L2CAP
        :type packet: Packet
        """
        self.send('l2cap', ATT_Hdr()/packet)

    def error_response(self, request, handle, reason):
        """Sends an ATT Error Response

        :param int request: Request that generated this error
        :param int handle: Attribute handle that generated this error
        :param int ecode: Reason why this error has been generated
        """
        self.send_data(ATT_Error_Response(
                request=request,
                handle=handle,
                ecode=reason
            )
        )

    def exch_mtu_request(self, mtu):
        """Sends an ATT Exchange MTU Request

        :param int mtu: Maximum Transmission Unit
        """
        # Update local MTU first
        logger.debug("[att] sending an MTU exchange request (mtu: %d)", mtu)
        self.send_data(ATT_Exchange_MTU_Request(
            mtu=mtu
        ))

    def exch_mtu_response(self, mtu):
        """Sends an ATT Exchange MTU Response

        :param int mtu: Maximum Transmission Unit
        """
        logger.debug("[att] sending an MTU exchange response (mtu: %d)", mtu)
        self.send_data(ATT_Exchange_MTU_Response(
            mtu=mtu
        ))


    def find_info_request(self, start, end):
        """Sends an ATT Find Information Request
        """
        self.send_data(ATT_Find_Information_Request(
            start=start,
            end=end
        ))

    def  find_info_response(self, form, handles):
        """Sends an ATT Find Information Response
        """

        self.send_data(ATT_Find_Information_Response(
            format=form,
            handles=handles
        ))

    def find_by_type_value_request(self, start, end, type_uuid, value):
        """Sends an ATT Find By Type Value Request
        """
        self.send_data(ATT_Find_By_Type_Value_Request(
            start=start,
            end=end,
            uuid=type_uuid,
            data=value
        ))

    def  find_by_type_value_response(self, handles: List[ATT_Handle]):
        """Sends an ATT Find By Type Value Response
        """
        self.send_data(ATT_Find_By_Type_Value_Response(
            handles=handles
        ))

    def read_by_type_request(self, start, end, uuid):
        """Sends an ATT Read By Type Request

        :param int start: First requested handle number
        :param int end: Last requested handle number
        :param uuid: 16-bit or 128-bit attribute UUID
        """
        self.send_data(ATT_Read_By_Type_Request(
            start=start,
            end=end,
            uuid=uuid
        ))


    def read_by_type_request_128bit(self, start, end, uuid1, uuid2):
        """Sends an ATT Read By Type Request with 128-bit UUID

        :param int start: First requested handle number
        :param int end: Last requested handle number
        :param uuid1: UUID part 1
        :param uuid2: UUID part 2
        """
        self.send_data(ATT_Read_By_Type_Request_128bit(
            start=start,
            end=end,
            uuid1=uuid1,
            uuid2=uuid2
        ))

    def read_by_type_response(self, item_length, handles):
        """Sends an ATT Read By Type Response

        :param int item_length: Length of a handle item
        :param list handles: List of handles (each item stored on `item_length` bytes)
        """
        self.send_data(ATT_Read_By_Type_Response(
            len=item_length,
            handles=handles
        ))


    def read_request(self, gatt_handle):
        """Sends an ATT Read Request
        """
        self.send_data(ATT_Read_Request(
            gatt_handle=gatt_handle
        ))

    def read_response(self, value):
        """Sends an ATT Read Response
        """
        self.send_data(ATT_Read_Response(
            value=value
        ))


    def read_blob_request(self, handle, offset):
        """Sends an ATT Read Blob Request

        :param int handle: Handle of attribute to read from
        :param int offset: Offset of the first octet to be read
        """
        self.send_data(ATT_Read_Blob_Request(
            gatt_handle=handle,
            offset=offset
        ))

    def read_blob_response(self, value):
        """Sends an ATT Read Blob Response

        :param value: Value read
        """
        self.send_data(ATT_Read_Blob_Response(
            value=value
        ))

    def read_multiple_request(self, handles):
        """Sends an ATT Read Multiple Request

        :param handles: list of handles
        """
        self.send_data(ATT_Read_Multiple_Request(
            handles=handles
        ))

    def read_multiple_response(self, values):
        """Sends an ATT Read Multiple Response

        :param values: List of multiple values
        """
        self.send_data(ATT_Read_Multiple_Response(
            values=values
        ))


    def read_by_group_type_request(self, start, end, uuid):
        """Sends an ATT Read By Group Type Request

        :param int start: First requested handle number
        :param int end: Last requested handle number
        :param uuid: 16-bit or 128-bit group UUID
        """
        self.send_data(ATT_Read_By_Group_Type_Request(
            start=start,
            end=end,
            uuid=uuid
        ))

    def read_by_group_type_response(self, length, data):
        """Sends an ATT Read By Group Type Response

        :param int length: Size of each attribute data
        :param data: List of attribute data
        """
        self.send_data(ATT_Read_By_Group_Type_Response(
            length=length,
            data=data
        ))

    def write_request(self, handle, data):
        """Sends an ATT Write Request

        :param int handle: Attribute handle to write into
        :param data: Data to write
        """
        self.send_data(ATT_Write_Request(
            gatt_handle=handle,
            data=data
        ))

    def write_response(self):
        """Sends an ATT Write Response
        """
        self.send_data(ATT_Write_Response())

    def write_command(self, handle, data):
        """Sends an ATT Write Command
        """
        self.send_data(ATT_Write_Command(
            gatt_handle=handle,
            data=data
        ))


    def prepare_write_request(self, handle, offset, data):
        """Sends an ATT Write Request

        :param int handle: Attribute handle
        :param int offset: Offset of the data to write
        :param data: Data to write
        """
        self.send_data(ATT_Prepare_Write_Request(
            gatt_handle=handle,
            offset=offset,
            data=data
        ))

    def prepare_write_response(self, handle, offset, data):
        """Sends an ATT Write Response

        :param int handle: Attribute handle
        :param int offset: Offset of the data to write
        :param data: Data to write
        """
        self.send_data(ATT_Prepare_Write_Response(
            gatt_handle=handle,
            offset=offset,
            data=data
        ))

    def execute_write_request(self, flags):
        """Sends an ATT Execute Write Request

        :param flags: Flags
        """
        self.send_data(ATT_Execute_Write_Request(
            flags=flags
        ))

    def execute_write_response(self):
        """Sends an ATT Execute Write Response
        """
        self.send_data(ATT_Execute_Write_Response())


    def handle_value_notification(self, handle, value):
        """Sends an ATT Handle Value Notification

        :param int handle: Attribute handle
        :param value: Attribute value
        """
        self.send_data(ATT_Handle_Value_Notification(
            gatt_handle=handle,
            value=value
        ))

    def handle_value_indication(self, handle, value):
        """Sends an ATT Handle Value Indication

        :param int handle: Attribute handle
        :param value: Attribute value
        """
        self.send_data(ATT_Handle_Value_Indication(
            gatt_handle=handle,
            value=value
        ))

    def handle_value_confirmation(self):
        """Sends an ATT Handle Value Confirmation

        Not supported yet
        """
        self.send_data(ATT_Handle_Value_Confirmation())
