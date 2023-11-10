"""
BLE ATT layer manager

This layer manager mostly translates Scapy ATT packets into GATT messages required by the GATT
layer, and exposes an interface to the GATT layer in order to allow ATT packets to be forged
and sent to the underlying layer (L2CAP).
"""
from typing import List
from scapy.layers.bluetooth import ATT_Error_Response, ATT_Exchange_MTU_Request, \
    ATT_Exchange_MTU_Response, ATT_Execute_Write_Request, ATT_Execute_Write_Response, \
    ATT_Find_By_Type_Value_Request, ATT_Find_By_Type_Value_Response, ATT_Find_Information_Request, \
    ATT_Find_Information_Response, ATT_Prepare_Write_Request, ATT_Prepare_Write_Response, \
    ATT_Read_Blob_Request, ATT_Handle_Value_Indication, ATT_Handle_Value_Notification, \
    ATT_Read_Blob_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response, \
    ATT_Read_By_Type_Request, ATT_Read_By_Type_Response, ATT_Read_Multiple_Request, ATT_Read_Multiple_Response, \
    ATT_Read_Request, ATT_Read_Response, ATT_Write_Command, ATT_Write_Response, ATT_Write_Request, \
    ATT_Read_By_Type_Request_128bit, ATT_Hdr, ATT_Handle
from scapy.packet import bind_layers, Packet

from whad.ble.stack.att.constants import BleAttOpcode, SecurityProperty, SecurityAccess

from whad.common.stack import Layer, alias, source, instance

#from whad.ble.stack.gatt import  Gatt
from whad.ble.stack.gatt.message import GattExecuteWriteRequest, GattExecuteWriteResponse, \
    GattFindInfoResponse, GattHandleValueIndication, GattHandleValueNotification, GattPrepareWriteRequest, \
    GattPrepareWriteResponse, GattReadByGroupTypeResponse, GattErrorResponse, \
    GattFindByTypeValueRequest, GattFindByTypeValueResponse, GattFindInfoRequest, GattReadByTypeResponse, \
    GattReadRequest, GattReadResponse, GattReadBlobRequest, GattReadBlobResponse, GattReadMultipleRequest, \
    GattReadMultipleResponse, GattWriteCommand, GattWriteRequest, GattWriteResponse, GattPrepareWriteRequest, \
    GattPrepareWriteResponse, GattExecuteWriteRequest, GattExecuteWriteResponse, \
    GattExchangeMtuResponse, GattReadByGroupTypeRequest, GattReadByTypeRequest, GattReadByTypeRequest128

# Add missing ATT_Handle_Value_Confirmation class
class ATT_Handle_Value_Confirmation(Packet):
    name = "Handle Value Confirmation"

# Bind ATT_Handle_Value_Confirmation with ATT_Hdr
bind_layers(ATT_Hdr, ATT_Handle_Value_Confirmation, opcode=BleAttOpcode.HANDLE_VALUE_CONFIRMATION)


@alias('att')
class ATTLayer(Layer):

    ##########################################
    # Incoming requests and responses
    ##########################################

    @instance('l2cap')
    def on_packet(self, instance, att_pkt):
        """Dispatch ATT packet.
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

    def on_error_response(self, error_resp):
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

    def on_exch_mtu_request(self, mtu_req):
        """Handle ATT Exchange MTU request, update L2CAP TX MTU and returns
        our MTU.

        :param ATT_Exchange_MTU_Request mtu_req: MTU request
        """
        # Update L2CAP Client MTU
        self.get_layer('l2cap').set_remote_mtu(mtu_req.mtu)

        # Send back our MTU.
        self.send_data(ATT_Exchange_MTU_Response(
            mtu=self.get_layer('l2cap').get_local_mtu()
        ))

    def on_exch_mtu_response(self, mtu_resp):
        """Update L2CAP remote MTU based on ATT_Exchange_MTU_Response.

        :param mtu_resp ATT_Exchange_MTU_Response: MTU response
        """
        self.get_layer('l2cap').set_remote_mtu(mtu_resp.mtu)

        # Forward to GATT
        #self.send('gatt', GattExchangeMtuResponse(mtu=mtu_resp.mtu),
        #          tag='XCHG_MTU_RESP')


    def on_find_info_request(self, request):
        """Handle ATT Find Information Request

        :param ATT_Find_Information_Request request: Request
        """
        self.send('gatt', GattFindInfoRequest(
                request.start,
                request.end
            ), tag='FIND_INFO_REQ'
        )

    def on_find_info_response(self, response):
        """Handle ATT Find Information Response
        """
        handles = b''.join([item.build() for item in response.handles])
        self.send('gatt', GattFindInfoResponse.from_bytes(
                response.format,
                handles
            ), tag='FIND_INFO_RESP',
        )

    def on_find_by_type_value_request(self, request):
        self.send('gatt', GattFindByTypeValueRequest(
                request.start,
                request.end,
                request.uuid,
                request.data
            )
        )

    def on_find_by_type_value_response(self, response):
        handles = b''.join([item.build() for item in response.handles])
        self.send('gatt', GattFindByTypeValueResponse.from_bytes(handles))

    def on_read_by_type_request(self, request):
        """Handle read by type request
        """
        self.send('gatt', GattReadByTypeRequest(
            request.start,
            request.end,
            request.uuid
        ))

    def on_read_by_type_request_128bit(self, request):
        """Handle ATT Read By Type Request 128-bit UUID
        """
        self.send('gatt',
            request.start,
            request.end,
            request.uuid1,
            request.uuid2
        )

    def on_read_by_type_response(self, response: GattReadByTypeResponse):
        """Handle read by type response
        """
        # Must rebuild handles payload as bytes, since scapy parsed it :(
        handles = b''.join([item.build() for item in response.handles])
        self.send('gatt', GattReadByTypeResponse.from_bytes(
                response.len,
                handles
            )
        )

    def on_read_request(self, request):
        """Handle ATT Read Request
        """
        self.send('gatt', GattReadRequest(
                request.gatt_handle
            )
        )

    def on_read_response(self, response):
        """Handle ATT Read Response
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

    def on_read_blob_request(self, request):
        """Handle ATT Read Blob Request
        """
        self.send('gatt', GattReadBlobRequest(
                request.gatt_handle,
                request.offset
            )
        )

    def on_read_blob_response(self, response):
        """Handle ATT Read Blob Response

        :param response: ATT response if provided, None otherwise.
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

    def on_read_multiple_request(self, request):
        """Handle ATT Read Multiple Request
        """
        self.send('gatt',GattReadMultipleRequest(request.handles))

    def on_read_multiple_response(self, response):
        """Handle ATT Read Multiple Response
        """
        self.send('gatt', GattReadMultipleResponse(response.values))

    def on_read_by_group_type_request(self, request):
        """Handle ATT Read By Group Type Request
        """
        self.send('gatt', GattReadByGroupTypeRequest(
                request.start,
                request.end,
                request.uuid
            )
        )

    def on_read_by_group_type_response(self, response):
        """Handle ATT Read By Group Type Response
        """
        self.send('gatt', GattReadByGroupTypeResponse.from_bytes(
                response.length,
                response.data
            )
        )

    def on_write_request(self, request):
        """Handle ATT Write Request
        """
        self.send('gatt', GattWriteRequest(
                request.gatt_handle,
                request.data
            )
        )

    def on_write_response(self, response):
        """Handle ATT Write Response
        """
        self.send('gatt', GattWriteResponse())

    def on_write_command(self, command):
        """Handle ATT Write Command
        """
        self.send('gatt', GattWriteCommand(
                command.gatt_handle,
                command.data
            )
        )

    def on_prepare_write_request(self, request):
        """Handle ATT Prepare Write Request
        """
        self.send('gatt', GattPrepareWriteRequest(
                request.gatt_handle,
                request.offset,
                request.data
            )
        )

    def on_prepare_write_response(self, response):
        """Handle ATT Prepare Write Response
        """
        self.send('gatt', GattPrepareWriteResponse(
                response.gatt_handle,
                response.offset,
                response.data
            )
        )

    def on_execute_write_request(self, request):
        """Handle ATT Execute Write Request
        """
        self.send('gatt', GattExecuteWriteRequest(
                request.flags
            )
        )

    def on_execute_write_response(self, response):
        """Handle ATT Execute Write Response
        """
        self.send('gatt', GattExecuteWriteResponse())

    def on_handle_value_notification(self, notif):
        """Handle ATT Handle Value Notification
        """
        self.send('gatt', GattHandleValueNotification(
                notif.gatt_handle,
                notif.value
            )
        )

    def on_handle_value_indication(self, notif):
        """Handle ATT Handle Value indication
        """
        self.send('gatt', GattHandleValueIndication(
                notif.gatt_handle,
                notif.value
            )
        )

    ##########################################
    # Outgoing requests and responses
    ##########################################

    def send_data(self, packet):
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
        self.get_layer('l2cap').set_local_mtu(mtu)
        self.send_data(ATT_Exchange_MTU_Request(
            mtu=mtu
        ))

    def exch_mtu_response(self, mtu):
        """Sends an ATT Exchange MTU Response

        :param int mtu: Maximum Transmission Unit
        """
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

    def  find_info_response(self, format, handles):
        """Sends an ATT Find Information Response
        """

        self.send_data(ATT_Find_Information_Response(
            format=format,
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
