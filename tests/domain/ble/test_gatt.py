'''BLE stack ATT/GATT layers unit tests.
'''
import pytest

from scapy.layers.bluetooth import *

from whad.common.stack import alias
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.ble.stack.att import ATTLayer, ATT_Handle_Value_Confirmation
from whad.ble.stack.att.constants import BleAttOpcode, BleAttErrorCode
from whad.ble.utils.att import UUID
from whad.ble.stack.att.exceptions import *

from whad.ble.stack.gatt import GattLayer, GattClient, GattServer
from whad.ble.stack.gatt.message import *
from whad.ble.stack.gatt.exceptions import GattTimeoutException

from whad.ble.profile import GenericProfile, Characteristic, PrimaryService as BlePrimaryService
from whad.ble.profile.service import PrimaryService

############################
# L2CAP and ATT mocks
############################

@alias('l2cap')
class L2capMock(Sandbox):
    pass
L2capMock.add(ATTLayer)

@alias('att')
class AttMock(Sandbox):
    
    def read_by_group_type_request(self, start, end, uuid):
        pass

    def read_request(self, gatt_handle=None):
        pass

    def read_blob_request(self, handle, offset):
        pass

    def read_by_type_request(self, start, end, uuid):
        pass

    def get_local_mtu(self):
        return 23
    
    def write_request(self, handle, value):
        pass

    def prepare_write_request(self, handle, offset, value):
        pass

    def execute_write_request(self, flags):
        pass

    def exch_mtu_request(self, mtu):
        pass

    def find_info_request(self, handle, end_handle):
        pass


######################
# GATT features tests
######################

class GattTest(object):

    @pytest.fixture
    def l2cap_instance(self):
        return L2capMock(target=ATTLayer)
    
    @pytest.fixture
    def att(self, l2cap_instance):
        return l2cap_instance.get_layer('att')
    
    @pytest.fixture
    def gatt(self, l2cap_instance):
        return l2cap_instance.get_layer('gatt')
    

class TestGatt(GattTest):
    '''Test GATT internal mechanics (message queue)
    '''
    
    @pytest.fixture
    def att(self):
        AttMock.add(GattClient)
        return AttMock(target=GattClient)
    
    @pytest.fixture
    def gatt(self, att):
        return att.get_layer('gatt')
    
    def test_wait_for_message(self, gatt, att):
        # Send a write request to Gatt
        att.send('gatt', GattWriteResponse())
        assert isinstance(
            gatt.wait_for_message(GattWriteResponse),
            GattWriteResponse
        )


#######################
# GATT/L2CAP tests
#######################


class TestAttToL2CAP(GattTest):
    '''Test ATT features.
    '''

    def test_find_info_req(self, l2cap_instance, att):
        '''Test ATTLayer `find_info_request()` function
        '''
        att.find_info_request(0, 1)
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Find_Information_Request(
                start=0,
                end=1
            )
        ))

    def test_find_info_resp(self, l2cap_instance, att):
        att.find_info_response(format=1, handles=b'test')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Find_Information_Response(
                format=1,
                handles=b'test'
            )
        ))

    def test_find_by_type_value_req(self, l2cap_instance, att):
        att.find_by_type_value_request(0, 1, UUID(0x2800), b'test')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Find_By_Type_Value_Request(
                start=0,
                end=1,
                uuid=UUID(0x2800),
                data=b'test'
            )
        ))
    
    def test_read_by_type_request(self, l2cap_instance, att):
        att.read_by_type_request(0, 1, UUID(0x2800))
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_By_Type_Request(
                start=0,
                end=1,
                uuid=UUID(0x2800)
            )
        ))

    def test_read_by_type_response(self, l2cap_instance, att):
        att.read_by_type_response(2, [b'aa',b'bb'])
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_By_Type_Response(
                len=2,
                handles=[b'aa', b'bb']
            )
        ))

    def test_read_request(self, l2cap_instance, att):
        att.read_request(10)
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Request(gatt_handle=10)
        ))

    def test_read_response(self, l2cap_instance, att):
        att.read_response(b'testvalue')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Response(value=b'testvalue')
        ))

    def test_read_blob_request(self, l2cap_instance, att):
        att.read_blob_request(42, 10)
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Blob_Request(
                gatt_handle=42,
                offset=10
            )
        ))

    def test_read_blob_response(self, l2cap_instance, att):
        att.read_blob_response(b'response')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Blob_Response(
                value=b'response'
            )
        ))

    def test_read_multiple_request(self, l2cap_instance, att):
        att.read_multiple_request([1,2,3])
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Multiple_Request(
                handles=[1,2,3]
            )
        ))

    def test_read_multiple_response(self, l2cap_instance, att):
        att.read_multiple_response([b'aaa', b'bbb', b'ccc'])
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Multiple_Response(
                values=[b'aaa',b'bbb', b'ccc']
            )
        ))

    def test_read_by_group_type_request(self, l2cap_instance, att):
        att.read_by_group_type_request(0, 1, UUID(0x2900))
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_By_Group_Type_Request(
                start=0,
                end=1,
                uuid=UUID(0x2900)
            )
        ))

    def test_read_by_group_type_response(self, l2cap_instance, att):
        att.read_by_group_type_response(2, [b'aa', b'bb', b'cc', b'dd'])
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_By_Group_Type_Response(
                length=2,
                data=[b'aa', b'bb', b'cc', b'dd']
            )
        ))

    def test_write_request(self, l2cap_instance, att):
        att.write_request(33, b'toto')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Write_Request(
                gatt_handle = 33,
                data=b'toto'
            )
        ))

    def test_write_response(self, l2cap_instance, att):
        att.write_response()
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Write_Response()
        ))
    
    def test_write_command(self, l2cap_instance, att):
        att.write_command(22, b'foobar')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Write_Command(
                gatt_handle=22,
                data=b'foobar'
            )
        ))

    def test_prepare_write_request(self, l2cap_instance, att):
        att.prepare_write_request(12, 55, b'bar')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Prepare_Write_Request(
                gatt_handle=12,
                offset=55,
                data=b'bar'
            )
        ))

    def test_prepare_write_response(self, l2cap_instance, att):
        att.prepare_write_response(5, 10, b'something')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Prepare_Write_Response(
                gatt_handle=5,
                offset=10,
                data=b'something'
            )
        ))

    def test_execute_write_request(self, l2cap_instance, att):
        att.execute_write_request(0x42)
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Execute_Write_Request(
                flags=0x42
            )
        ))

    def test_execute_write_response(self, l2cap_instance, att):
        att.execute_write_response()
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Execute_Write_Response()
        ))

    def test_value_notification(self, l2cap_instance, att):
        att.handle_value_notification(93, b'nothinghere')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Handle_Value_Notification(
                gatt_handle=93,
                value=b'nothinghere'
            )
        ))

    def test_value_indication(self, l2cap_instance, att):
        att.handle_value_indication(93, b'nothinghere')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Handle_Value_Indication(
                gatt_handle=93,
                value=b'nothinghere'
            )
        ))

    def test_value_confirmation(self, l2cap_instance, att):
        att.handle_value_confirmation()
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Handle_Value_Confirmation()
        ))


#####################
# ATT/GATT tests
#####################


class TestAttToGatt(GattTest):
    '''Test ATT -> GATT communication
    '''

    @pytest.fixture
    def l2cap_instance(self):
        ATTLayer.add(GattLayer)
        return L2capMock(target=ATTLayer)
    
    @pytest.fixture
    def att(self, l2cap_instance):
        return l2cap_instance.get_layer('att')

    def test_find_info_request(self, l2cap_instance, att):
        l2cap_instance.send('att', ATT_Hdr() / ATT_Find_Information_Request(
            start=12,
            end=42
        ))
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.FIND_INFO_REQUEST,
                handle=12,
                ecode=BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )
        ))

    def test_find_by_type_value_request(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Find_By_Type_Value_Request(
                start=0,
                end=0x42,
                uuid=UUID(0x2800),
                data=b'foobar'
            )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST,
                handle=0,
                ecode=BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )
        ))

    def test_read_by_type_request(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Read_By_Type_Request(
                start=13,
                end=45,
                uuid=UUID(0x1234)
            )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.READ_BY_TYPE_REQUEST,
                handle=13,
                ecode=BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )
        ))

    def test_read_by_group_type_request(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Read_By_Group_Type_Request(
                start=27,
                end=45,
                uuid=UUID(0x1234)
            )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.READ_BY_GROUP_TYPE_REQUEST,
                handle=27,
                ecode=BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )
        ))

    def test_read_request(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Read_Request(
                gatt_handle=21
           )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.READ_REQUEST,
                handle=21,
                ecode=BleAttErrorCode.INVALID_HANDLE
            )
        ))

    def test_read_blob_request(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Read_Blob_Request(
                gatt_handle=7,
                offset=8
           )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.READ_BLOB_REQUEST,
                handle=7,
                ecode=BleAttErrorCode.INVALID_HANDLE
            )
        ))

    def test_read_multiple_request(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Read_Multiple_Request(
                handles=[1,2,3]
            )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.READ_MULTIPLE_REQUEST,
                handle=1,
                ecode=BleAttErrorCode.INVALID_HANDLE
            )
        ))

    def test_write_request(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Write_Request(
                gatt_handle=44,
                data=b'somethinguseful'
            )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.WRITE_REQUEST,
                handle=44,
                ecode=BleAttErrorCode.INVALID_HANDLE
            )
        ))

    def test_write_command(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Write_Command(
                gatt_handle=88,
                data=b'somethinguseful'
            )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.WRITE_COMMAND,
                handle=88,
                ecode=BleAttErrorCode.INVALID_HANDLE
            )
        ))

    def test_prepare_write_request(self, l2cap_instance, att):
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Prepare_Write_Request(
                gatt_handle=27,
                offset=3,
                data=b'somethinguseful'
            )
        )
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.PREPARE_WRITE_REQUEST,
                handle=27,
                ecode=BleAttErrorCode.INVALID_HANDLE
            )
        ))


#############################################
# GATT Client procedures Tests
#############################################

class GattDeviceModel(GenericProfile):

    device = BlePrimaryService(
        uuid=UUID(0x1800),
        device_name=Characteristic(
            uuid=UUID(0x2A00),
            permissions=['read', 'write'],
            notify=True,
            value=b'TestDevice'
        ),
    )


class TestGattClientProcedures(GattTest):

    @pytest.fixture
    def att(self):
        AttMock.add(GattClient)
        return AttMock(target=GattClient)
       
    @pytest.fixture
    def gatt(self, att):
        return att.get_layer('gatt')
    
    def test_discover_primary_services_endhandle(self, att, gatt):
        # Build primary service discovery response
        resp0 = GattReadByGroupTypeResponse(6)
        resp0.append(GattGroupTypeItem(1, 2, UUID(0x1800).packed))
        resp1 = GattReadByGroupTypeResponse(6)
        resp1.append(GattGroupTypeItem(3, 0xFFFF, UUID(0x1801).packed))
        messages = [
            resp0,
            resp1
        ]

        # Send messages to Gatt client in order to get them stacked
        # in its reception queue
        for msg in messages:
            gatt.on_gatt_message(msg)
        
        # Start primary service discovery procedure
        services = list(gatt.discover_primary_services())
        assert len(services) == 2
                
    def test_discover_primary_services_attrerror(self, att, gatt):
        # Build primary service discovery response
        resp0 = GattReadByGroupTypeResponse(6)
        resp0.append(GattGroupTypeItem(1, 2, UUID(0x1800).packed))
        resp1 = GattErrorResponse(BleAttOpcode.READ_BY_GROUP_TYPE_REQUEST, 3, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)
        messages = [
            resp0,
            resp1
        ]

        # Send messages to Gatt client in order to get them stacked
        # in its reception queue
        for msg in messages:
            gatt.on_gatt_message(msg)
        
        # Start primary service discovery procedure
        services = list(gatt.discover_primary_services())
        assert len(services)==1

    def test_discover_primary_services_fail(self, att, gatt):
        # Build primary service discovery response
        resp0 = GattReadByGroupTypeResponse(6)
        resp0.append(GattGroupTypeItem(1, 2, UUID(0x1800).packed))
        messages = [
            resp0,
        ]

        # Send messages to Gatt client in order to get them stacked
        # in its reception queue
        for msg in messages:
            gatt.on_gatt_message(msg)
        
        # Start primary service discovery procedure
        with pytest.raises(GattTimeoutException):
            services = list(gatt.discover_primary_services())


    def test_discover_secondary_services_endhandle(self, att, gatt):
        # Build secondary service discovery response
        resp0 = GattReadByGroupTypeResponse(6)
        resp0.append(GattGroupTypeItem(1, 2, UUID(0x1800).packed))
        resp1 = GattReadByGroupTypeResponse(6)
        resp1.append(GattGroupTypeItem(3, 0xFFFF, UUID(0x1801).packed))
        messages = [
            resp0,
            resp1
        ]

        # Send messages to Gatt client in order to get them stacked
        # in its reception queue
        for msg in messages:
            gatt.on_gatt_message(msg)
        
        # Start primary service discovery procedure
        services = list(gatt.discover_primary_services())
        assert len(services) == 2

    def test_discover_secondary_services_attrerror(self, att, gatt):
        # Build primary secondary discovery response
        resp0 = GattReadByGroupTypeResponse(6)
        resp0.append(GattGroupTypeItem(1, 2, UUID(0x1800).packed))
        resp1 = GattErrorResponse(BleAttOpcode.READ_BY_GROUP_TYPE_REQUEST, 3, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)
        messages = [
            resp0,
            resp1
        ]

        # Send messages to Gatt client in order to get them stacked
        # in its reception queue
        for msg in messages:
            gatt.on_gatt_message(msg)
        
        # Start primary service discovery procedure
        services = list(gatt.discover_primary_services())
        assert len(services)==1

    def test_discover_secondary_services_fail(self, att, gatt):
        # Build secondary service discovery response
        resp0 = GattReadByGroupTypeResponse(6)
        resp0.append(GattGroupTypeItem(1, 2, UUID(0x1800).packed))
        messages = [
            resp0,
        ]

        # Send messages to Gatt client in order to get them stacked
        # in its reception queue
        for msg in messages:
            gatt.on_gatt_message(msg)
        
        # Start primary service discovery procedure
        with pytest.raises(GattTimeoutException):
            services = list(gatt.discover_primary_services())

    def test_discover_characteristics(self, att, gatt):
        '''Test Gatt Client service characteristics discovery
        '''
        # Generate a GattReadByTypeResponse
        resp0 = GattReadByTypeResponse(7)
        resp0.append(GattAttributeValueItem(
            2,
            b'\x02' + struct.pack('<H', 3) + UUID(0x2A01).packed
        ))
        resp0.append(GattAttributeValueItem(
            4,
            b'\x02' + struct.pack('<H', 5) + UUID(0x2A02).packed
        ))
        resp0.append(GattAttributeValueItem(
            6,
            b'\x02' + struct.pack('<H', 7) + UUID(0x2A03).packed
        ))

        # Send this response to the message queue
        gatt.on_gatt_message(resp0)
        # Along with a GATT error message
        gatt.on_gatt_message(GattErrorResponse(
            BleAttOpcode.READ_BY_TYPE_RESPONSE,
            8,
            BleAttErrorCode.ATTRIBUTE_NOT_FOUND
        ))

        # And ask our GATT client to discover the characteristics
        # of a fictitious service.
        characs = list(gatt.discover_characteristics(PrimaryService(UUID(0x1800), 1, 7)))

        # Check discovered characteristics
        assert characs[0].handle == 2
        assert characs[0].value_handle == 3
        assert characs[0].uuid == UUID(0x2A01)
        assert characs[1].handle == 4
        assert characs[1].value_handle == 5
        assert characs[1].uuid == UUID(0x2A02)
        assert characs[2].handle == 6
        assert characs[2].value_handle == 7
        assert characs[2].uuid == UUID(0x2A03)

    def test_discover_characteristic_descriptors(self, att, gatt):
        '''Test GATT characteristic descriptors
        '''
        # We must provide a model filled with at least a service
        # And a characteristic
        model = GattDeviceModel()
        gatt.set_model(model)

        # We filled the message queue with prepared responses
        descriptors = GattFindInfoResponse(
            GattFindInfoResponse.FORMAT_HANDLE_UUID_16
        )
        descriptors.append(GattHandleUUIDItem(
            10,
            UUID(0x2B00)
        ))
        descriptors.append(GattHandleUUIDItem(
            11,
            UUID(0x2B01)
        ))
        gatt.on_gatt_message(descriptors)

        # We ask our GATT client to discover a characteristic descriptors
        # (won't do anything since ATT layer is a pure mock) but will
        # take our previous message as the corresponding answer
        descriptors = list(gatt.discover_characteristic_descriptors(
            model.device.device_name
        ))

        # Assert both descriptors returned by our message
        assert descriptors[0].handle == 10
        assert descriptors[0].uuid == UUID(0x2B00)
        assert descriptors[1].handle == 11
        assert descriptors[1].uuid == UUID(0x2B01)
                

    def test_characteristic_read(self, att, gatt):
        '''GATT Client characteristic basic read (length <= mtu)
        '''
        gatt.on_gatt_message(GattReadResponse(b'something'))
        result = gatt.read(12)
        assert result == b'something'

    def test_characteristic_read_fail(self, att, gatt):
        '''GATT client characteristic read with invalid handle
        '''
        gatt.on_gatt_message(GattErrorResponse(
            BleAttOpcode.READ_REQUEST,
            25,
            BleAttErrorCode.INVALID_HANDLE
        ))
        with pytest.raises(InvalidHandleValueError):
            gatt.read(25)

    def test_characteristic_read_blob(self, att, gatt):
        '''GATT client characteristic read as blob
        '''
        gatt.on_gatt_message(GattReadBlobResponse(b'foobar'))
        result = gatt.read_blob(13, offset=5)
        assert result == b'foobar'

    def test_characteristic_read_blob_fail(self, att, gatt):
        '''GATT client characteristic 
        '''
        gatt.on_gatt_message(GattErrorResponse(
            BleAttOpcode.READ_BLOB_REQUEST,
            13,
            BleAttErrorCode.INVALID_HANDLE
        ))
        with pytest.raises(InvalidHandleValueError):
            result = gatt.read_blob(13, offset=5)

    def test_characteristic_read_long(self, att, gatt):
        '''GATT client characteristic long read
        '''
        first_part = b'A'*22
        second_part = b'B'*12
        gatt.on_gatt_message(GattReadBlobResponse(first_part))
        gatt.on_gatt_message(GattReadBlobResponse(second_part))
        result = gatt.read_long(45)
        assert result == (first_part + second_part)
    
    def test_characteristic_read_long_short(self, att, gatt):
        '''GATT client characteristic long read on short value
        '''
        first_part = b'B'*12
        gatt.on_gatt_message(GattReadBlobResponse(first_part))
        result = gatt.read_long(45)
        assert result == first_part

    def test_characteristic_write(self, att, gatt):
        '''GATT client characteristic write (length <= mtu)
        '''
        gatt.on_gatt_message(GattWriteResponse())
        assert gatt.write(51, b'something') == True

    def test_characteristic_write_long(self, att, gatt):
        '''GATT client characteristic write (lenght > mtu)
        '''
        first_part = b'A'*(23 - 5)
        second_part = b'B'*12
        gatt.on_gatt_message(GattPrepareWriteResponse(11, 0, first_part))
        gatt.on_gatt_message(GattPrepareWriteResponse(11, 23-5, second_part))
        gatt.on_gatt_message(GattExecuteWriteResponse())
        assert gatt.write(11, first_part+second_part) == True

    def test_characteristic_read_by_uuid(self, att, gatt):
        '''GATT client characteristic read by UUID
        '''
        char_value = b'something'
        resp = GattReadByTypeResponse(len(char_value) + 2)
        resp.append(GattAttributeValueItem(77, char_value))
        gatt.on_gatt_message(resp)
        result = gatt.read_characteristic_by_uuid(UUID(0x1234), 77, 79)
        assert result == char_value

    def test_characteristic_read_by_uuid_fail(self, att, gatt):
        '''GATT client characteristic read by UUID (invalid handle)
        '''
        gatt.on_gatt_message(GattErrorResponse(
            BleAttOpcode.READ_BY_TYPE_REQUEST,
            78,
            BleAttErrorCode.INVALID_HANDLE
        ))
        with pytest.raises(InvalidHandleValueError):
            gatt.read_characteristic_by_uuid(UUID(0x1234), 78, 79)

    def test_set_mtu(self, att, gatt):
        '''GATT client MTU exchange
        '''
        gatt.on_gatt_message(GattExchangeMtuResponse(100))
        assert gatt.set_mtu(100) == 100

    def test_set_mtu_rejected(self, att, gatt):
        '''GATT client MTU exchange (request rejected)
        '''
        gatt.on_gatt_message(GattExchangeMtuResponse(23))
        assert gatt.set_mtu(100) == 23

    def test_set_mtu_fail(self, att, gatt):
        '''GATT client MTU exchange failure
        '''
        gatt.on_gatt_message(GattErrorResponse(
            BleAttOpcode.EXCHANGE_MTU_REQUEST,
            0,
            BleAttErrorCode.REQUEST_NOT_SUPP
        ))
        with pytest.raises(UnsupportedRequestError):
            gatt.set_mtu(100)
