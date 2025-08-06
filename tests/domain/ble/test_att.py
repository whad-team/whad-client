'''BLE stack ATT layer unit tests.

This module provides different test cases to check that
the ATT layer is working as expected:

- TestGatt: checks that `wait_for_message()` works as expected
- TestAttToL2CAP: checks each ATT method sends the correct packet to L2CAP
- TestAttToGatt: checks ATT incoming packets are correctly forwarded to GATT layer

'''
import pytest

from scapy.layers.bluetooth import *

from whad.scapy.layers.bluetooth import ATT_Handle_Value_Confirmation

from whad.common.stack import alias
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.ble.stack.att import ATTLayer
from whad.ble.stack.att.constants import BleAttOpcode, BleAttErrorCode
from whad.ble.profile.attribute import UUID
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
    '''This is a mock ATT layer (sandboxed) used in ATT unit tests.
    '''
    
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
        '''Check if ATT layer `find_info_request()` sends
        the correct message to L2CAP.
        '''
        att.find_info_request(1, 1)
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Find_Information_Request(
                start=1,
                end=1
            )
        ))

    def test_find_info_resp(self, l2cap_instance, att):
        '''Check if ATT layer `find_info_response()` sends
        the correct message to L2CAP.
        '''
        att.find_info_response(form=1, handles=b'test')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Find_Information_Response(
                format=1,
                handles=b'test'
            )
        ))

    def test_find_by_type_value_req(self, l2cap_instance, att):
        '''Check if ATT layer `find_by_type_value_request()` sends
        the correct message to L2CAP.
        '''
        att.find_by_type_value_request(1, 1, UUID(0x2800), b'test')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Find_By_Type_Value_Request(
                start=1,
                end=1,
                uuid=UUID(0x2800),
                data=b'test'
            )
        ))

    def test_read_by_type_request(self, l2cap_instance, att):
        '''Check if ATT layer `read_by_type_request()` sends
        the correct message to L2CAP.
        '''
        att.read_by_type_request(1, 1, UUID(0x2800))
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_By_Type_Request(
                start=1,
                end=1,
                uuid=UUID(0x2800)
            )
        ))

    def test_read_by_type_response(self, l2cap_instance, att):
        '''Check if ATT layer `read_by_type_response()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `read_request()` sends
        the correct message to L2CAP.
        '''
        att.read_request(10)
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Request(gatt_handle=10)
        ))

    def test_read_response(self, l2cap_instance, att):
        '''Check if ATT layer `read_response()` sends
        the correct message to L2CAP.
        '''
        att.read_response(b'testvalue')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Response(value=b'testvalue')
        ))

    def test_read_blob_request(self, l2cap_instance, att):
        '''Check if ATT layer `read_blob_request()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `read_blob_response()` sends
        the correct message to L2CAP.
        '''
        att.read_blob_response(b'response')
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Blob_Response(
                value=b'response'
            )
        ))

    def test_read_multiple_request(self, l2cap_instance, att):
        '''Check if ATT layer `read_multiple_request()` sends
        the correct message to L2CAP.
        '''
        att.read_multiple_request([1,2,3])
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Multiple_Request(
                handles=[1,2,3]
            )
        ))

    def test_read_multiple_response(self, l2cap_instance, att):
        '''Check if ATT layer `read_multiple_response()` sends
        the correct message to L2CAP.
        '''
        att.read_multiple_response([b'aaa', b'bbb', b'ccc'])
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Multiple_Response(
                values=[b'aaa',b'bbb', b'ccc']
            )
        ))

    def test_read_by_group_type_request(self, l2cap_instance, att):
        '''Check if ATT layer `read_by_group_type_request()` sends
        the correct message to L2CAP.
        '''
        att.read_by_group_type_request(1, 1, UUID(0x2900))
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_By_Group_Type_Request(
                start=1,
                end=1,
                uuid=UUID(0x2900)
            )
        ))

    def test_read_by_group_type_response(self, l2cap_instance, att):
        '''Check if ATT layer `read_by_group_type_response()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `write_request()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `write_response()` sends
        the correct message to L2CAP.
        '''
        att.write_response()
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Write_Response()
        ))
    
    def test_write_command(self, l2cap_instance, att):
        '''Check if ATT layer `write_command()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `prepare_write_request()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `prepare_write_response()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `execute_write_request()` sends
        the correct message to L2CAP.
        '''
        att.execute_write_request(0x42)
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Execute_Write_Request(
                flags=0x42
            )
        ))

    def test_execute_write_response(self, l2cap_instance, att):
        '''Check if ATT layer `execute_write_response()` sends
        the correct message to L2CAP.
        '''
        att.execute_write_response()
        assert l2cap_instance.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Execute_Write_Response()
        ))

    def test_value_notification(self, l2cap_instance, att):
        '''Check if ATT layer `handle_value_notification()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `handle_value_indication()` sends
        the correct message to L2CAP.
        '''
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
        '''Check if ATT layer `handle_value_confirmation()` sends
        the correct message to L2CAP.
        '''
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
        L2capMock.add(ATTLayer)
        L2capMock.add(GattLayer)
        return L2capMock()

    @pytest.fixture
    def att(self, l2cap_instance):
        return l2cap_instance.get_layer('att')

    def test_find_info_request(self, l2cap_instance, att):
        '''Check ATT layer correctly processes an incoming
        ATT_Find_Information_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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
        '''Check ATT layer correctly processes an incoming
        ATT_Find_By_Type_Value_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
        l2cap_instance.send(
            'att',
            ATT_Hdr() / ATT_Find_By_Type_Value_Request(
                start=1,
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
                handle=1,
                ecode=BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )
        ))

    def test_read_by_type_request(self, l2cap_instance, att):
        '''Check ATT layer correctly processes an incoming
        ATT_Read_By_Type_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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
        '''Check ATT layer correctly processes an incoming
        ATT_Read_By_Group_Type_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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
        '''Check ATT layer correctly processes an incoming
        ATT_Read_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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
        '''Check ATT layer correctly processes an incoming
        ATT_Read_Blob_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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
        '''Check ATT layer correctly processes an incoming
        ATT_Read_Multiple_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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
        '''Check ATT layer correctly processes an incoming
        ATT_Write_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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
        '''Check ATT layer correctly processes an incoming
        ATT_Write_Command packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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
        '''Check ATT layer correctly processes an incoming
        ATT_Prepare_Write_Request packet (sent to default GATT
        layer that sends a reply through ATT layer).
        '''
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



