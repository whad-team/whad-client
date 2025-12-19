'''BLE stack GATT layer unit tests

This module provides two sets of tests to ensure the GATT layer
behaves as expected:

- TestGattClientProcedures: checks GATT client procedures implementation
- TestGattServerProcedures: checks GATT server procedures implementation

'''

import pytest

from scapy.layers.bluetooth import *

from whad.ble.profile.characteristic import CharacteristicValue
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.ble.stack.att import ATTLayer
from whad.ble.stack.att.constants import BleAttOpcode, BleAttErrorCode
from whad.ble.profile.attribute import UUID
from whad.ble.stack.att.exceptions import *

from whad.ble.stack.gatt import GattClient, GattServer
from whad.ble.stack.gatt.message import *
from whad.ble.stack.gatt.exceptions import GattTimeoutException

from whad.ble.profile import GenericProfile, Characteristic, PrimaryService as BlePrimaryService
from whad.ble.profile.service import PrimaryService

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


class GattClientSandbox(Sandbox):
    def get_local_mtu(self):
        return 23
    def set_local_mtu(self, mtu):
        pass
GattClientSandbox.add(ATTLayer)
GattClientSandbox.add(GattClient)

class TestGattClientProcedures(object):

    @pytest.fixture
    def sandbox(self):
        return GattClientSandbox()

    @pytest.fixture
    def att(self, sandbox):
        return sandbox.get_layer('att')

    @pytest.fixture
    def gatt(self, sandbox):
        return sandbox.get_layer('gatt')

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
        assert len(result) == 1
        assert isinstance(result[0], CharacteristicValue)
        assert result[0].value == char_value

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


class GattServerSandbox(Sandbox):
    def set_local_mtu(self, mtu):
        pass
    def set_remote_mtu(self, mtu):
        pass
    def get_local_mtu(self):
        return 23
    def get_conn_handle(self):
        return 1
GattServerSandbox.add(ATTLayer)
GattServerSandbox.add(GattServer)

class TestGattServerProcedures(object):

    @pytest.fixture
    def sandbox(self):
        return GattServerSandbox()
    
    @pytest.fixture
    def att(self, sandbox):
        return sandbox.get_layer('att')

    @pytest.fixture
    def gatt(self, sandbox):
        return sandbox.get_layer('gatt')
    
    def test_characteristic_notification(self, sandbox, gatt):
        model = GattDeviceModel()
        gatt.set_model(model)
        gatt.notify(model.device.device_name)
        sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Handle_Value_Notification(
                gatt_handle=model.device.device_name.handle,
                value=model.device.device_name.value
            )
        ))

    def test_characteristic_indication(self, sandbox, gatt):
        model = GattDeviceModel()
        gatt.set_model(model)
        gatt.indicate(model.device.device_name)
        sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Handle_Value_Indication(
                gatt_handle=model.device.device_name.handle,
                value=model.device.device_name.value
            )
        ))

    def test_find_info_request(self, sandbox, gatt):
        model = GattDeviceModel()
        gatt.set_model(model)
        gatt.on_find_info_request(GattFindInfoRequest(
            1,
            1
        ))

        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Find_Information_Response(
                format=1,
                handles=b'\x01\x00\x00\x28'
            )
        ))
        
    def test_characteristic_read(self, sandbox, gatt):
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)
        gatt.on_read_request(GattReadRequest(
            handle=3
        ))
        sandbox.messages[0].data.show()
        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Response(
                value=b'something'
            )
        ))

    def test_characteristic_read_blob(self, sandbox, gatt):
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)
        gatt.on_read_blob_request(GattReadBlobRequest(
            3, 1
        ))
        
        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_Blob_Response(
                value=b'omething'
            )
        ))

    def test_characteristic_write(self, sandbox, gatt):
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)
        gatt.on_write_request(GattWriteRequest(
            handle=3,
            value=b'Foobar'
        ))
        assert model.device.device_name.value == b'Foobar'
        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Write_Response()
        ))

    def test_characteristic_write_command(self, sandbox, gatt):
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)
        gatt.on_write_request(GattWriteRequest(
            handle=3,
            value=b'Foobar'
        ))
        assert model.device.device_name.value == b'Foobar'
    

    def test_prepare_write(self, sandbox, gatt):
        '''Test GATT server prepare write request handling
        '''
        # Initialize our model
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)

        gatt.on_prepare_write_request(GattPrepareWriteRequest(
            3, 0, b'part1'
        ));

        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Prepare_Write_Response(
                gatt_handle=3,
                offset=0,
                data=b'part1'
            )
        ))

    def test_prepare_write_fail(self, sandbox, gatt):
        '''Test GATT server prepare write request handling
        when fed with an invalid handle
        '''
        # Initialize our model
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)

        gatt.on_prepare_write_request(GattPrepareWriteRequest(
            9, 0, b'part1'
        ));

        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.PREPARE_WRITE_REQUEST,
                handle=9,
                ecode=BleAttErrorCode.INVALID_HANDLE
            )
        ))

    def test_execute_write(self, sandbox, gatt):
        '''Test GATT server prepared request execution
        '''
        # Initialize our model
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)

        # We send two prepared write requests
        gatt.on_prepare_write_request(GattPrepareWriteRequest(
            3, 0, b'part1'
        ));
        gatt.on_prepare_write_request(GattPrepareWriteRequest(
            3, 5, b'part2'
        ));

        # And we execute the write requests
        gatt.on_execute_write_request(GattExecuteWriteRequest(
            flags=1
        ))

        # Check characteristic value
        assert model.device.device_name.value == b'part1part2'

        # Make sure we got a response
        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Execute_Write_Response()
        ))

    def test_find_by_type_value_request(self, sandbox, gatt):
        '''Test GATT server find type by
        '''
        # Initialize our model
        model = GattDeviceModel()
        model.device.device_name.value = b'test'
        gatt.set_model(model)

        # Search for Generic Device Profile service (0x1800)
        gatt.on_find_by_type_value_request(GattFindByTypeValueRequest(
            start=1,
            end=5,
            attr_type=UUID(0x2800),
            attr_value=UUID(0x1800).packed
        ))

        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Find_By_Type_Value_Response(
                handles=[ATT_Handle(
                    handle=1,
                    value=4
                )]
            )
        ))

    def test_find_by_type_value_request_fail(self, sandbox, gatt):
        '''Test GATT server find type by
        '''
        # Initialize our model
        model = GattDeviceModel()
        model.device.device_name.value = b'test'
        gatt.set_model(model)

        # Search for Generic Device Profile service (0x1800)
        gatt.on_find_by_type_value_request(GattFindByTypeValueRequest(
            start=1,
            end=5,
            attr_type=UUID(0x2800),
            attr_value=UUID(0x1F00).packed
        ))

        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Error_Response(
                request=BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST,
                handle=1,
                ecode=BleAttErrorCode.ATTRIBUTE_NOT_FOUND
            )
        ))


    def test_read_by_type_request(self, sandbox, gatt):
        '''Test GATT server read by type handling
        '''
        # Initialize our model
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)

        # Ask server to enumerate characteristics
        gatt.on_read_by_type_request(GattReadByTypeRequest(
            start=1,
            end=5,
            attr_type=UUID(0x2803)
        ))

        # Return a list of 1 characteristic (device_name)
        # with handle 3, UUID of 0x2A00, UUID len of 2
        # and properties of 0x1A (read, write, notify)
        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_By_Type_Response(
                len=7,
                handles=b'\x02\x00\x1a\x03\x00\x00\x2a'
            )
        ))

    def test_read_by_group_type_request(self, sandbox, gatt):
        '''Test GATT server read by group type handling
        '''
        # Initialize our model
        model = GattDeviceModel()
        model.device.device_name.value = b'something'
        gatt.set_model(model)

        # Ask server to enumerate characteristics
        gatt.on_read_by_group_type_request(GattReadByGroupTypeRequest(
            start=1,
            end=5,
            group_type=UUID(0x2803)
        ))

        # Return a list of 1 item
        # with start handle 2, end handle 4 and UUID 0x2A00
        assert sandbox.expect(LayerMessage(
            'att',
            'l2cap',
            ATT_Hdr() / ATT_Read_By_Group_Type_Response(
                length=6,
                data=b'\x02\x00\x04\x00\x00\x2A'
            )
        ))      

    def test_set_mtu(self, att, gatt):
        '''GATT server MTU exchange
        '''
        gatt.on_gatt_message(GattExchangeMtuResponse(100))
        assert gatt.set_mtu(100) == 100

    def test_set_mtu_rejected(self, att, gatt):
        '''GATT server MTU exchange (request rejected)
        '''
        gatt.on_gatt_message(GattExchangeMtuResponse(23))
        assert gatt.set_mtu(100) == 23

    def test_set_mtu_fail(self, att, gatt):
        '''GATT client MTU exchange failure
        '''
        gatt.on_gatt_message(GattExchangeMtuResponse(23))
        assert gatt.set_mtu(100) == 23
