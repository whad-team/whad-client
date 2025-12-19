"""
This module provides the :py:class:`.PeripheralDevice` class used to wrap all GATT operations
for a given connected device:

* discovering services, characteristics and descriptors
* reading a characteristic's value
* writing to a characteristic's value
* subscribing for notifications and indications
* exchanging MTU value with the remote peripheral
"""
import logging
from struct import unpack
from time import sleep
from typing import Iterator, Optional, Union, Type, TypeVar, List

from whad.ble.profile import PrimaryService
from whad.ble.profile.service import Service
from whad.ble.profile.services.defs import ServiceNotFound
from whad.ble.profile.characteristic import (
    Properties, Characteristic, CharacteristicValue,
    Descriptor,
)
from whad.ble.profile import GenericProfile
from whad.ble.profile.attribute import UUID, Attribute, InvalidUUIDException

logger = logging.getLogger(__name__)

PT = TypeVar("PT")

class RemoteAttribute:
    """Remote GATT attribute interface.

    This interface provides the required GATT procedure for any GATT attribute,
    based on an existing GATT layer corresponding to an existing connection already
    established with a remote GATT server.

    Each procedure is started by driving our underlying BLE stack.
    """

    def __init__(self, handle, gatt):
        """Initialize our GATT interface for the specified attribute.

        :param handle: Attribute handle
        :type  handle: int
        :param gatt: GATT layer instance (GATTClient)
        :type gatt: GattClient
        """
        self.__handle = handle
        self.__gatt = gatt

    @property
    def gatt(self):
        """GATT client accessor."""
        return self.__gatt

    def read(self, offset: int = 0) -> bytes:
        """Read the remote attribute using a GATT read or a GATT blob read procedure."""
        if offset == 0:
            return self.__gatt.read(self.__handle)
        return self.read_blob(offset)

    def read_blob(self, offset: int) -> bytes:
        """Read the remote attribute using a GATT blob read procedure."""
        return self.__gatt.read_blob(self.__handle, offset)

    def read_long(self) -> bytes:
        """Read the remote attribute using a combination of classic read
        and blob read requests, depending on the attribute value's length."""
        return self.__gatt.read_long(self.__handle)

    def write(self, value: bytes, without_response: bool = False) -> bool:
        """Write value into the remote attribute using a GATT write precedure."""
        if not without_response:
            result = self.__gatt.write(self.__handle, value)
        else:
            result = self.__gatt.write_command(self.__handle, value)

        # Force result to a boolean value (GATT client's write() method could
        # return None)
        return result == True

    def write_command(self, value: bytes) -> bool:
        """Write value into the remote attribute using a GATT write command procedure."""
        result = self.__gatt.write_command(self.__handle, value)

        # Force result to be a bool
        return result == True

    def write_long(self, value: bytes) -> bool:
        """Write value into the remote attribute using a GATT prepared write procedure."""
        result = self.__gatt.write_long(self.__handle, value)

        # Force result to a bool
        return result == True

class PeripheralCharacteristicDescriptor(Descriptor, RemoteAttribute):
    """Wrapper for a peripheral characteristic descriptor.
    """

    def __init__(self, descriptor, gatt):
        """Initialize a PeripheralCharacteristicDescriptor.

        :param CharacteristicDescriptor descriptor: Descriptor to wrap.
        :param GattClient gatt: GATT client to use for GATT operations (read/write).
        """
        Descriptor.__init__(self, descriptor.uuid, descriptor.handle, descriptor.value,
                                          descriptor.characteristic)
        RemoteAttribute.__init__(self, descriptor.handle, gatt)

    @property
    def value(self) -> bytes:
        """Transparent characteristic read.

        :return bytes: Characteristic value
        """
        value = self.read()

        # Update the underlying attribute value
        if Attribute.value.fset:
            Attribute.value.fset(self, value)
        return value

    @value.setter
    def value(self, value: bytes):
        """Transparent characteristic write.

        :param bytes val: Value to write into this characteristic
        """
        super().write(value)
        # Update the underlying attribute value
        if Attribute.value.fset:
            Attribute.value.fset(self, value)

    @property
    def cached_value(self) -> bytes:
        if Attribute.value.fget:
            return Attribute.value.fget(self)
        return b''

class PeripheralCharacteristicValue(CharacteristicValue, RemoteAttribute):
    """CharacteristicValue wrapper for peripheral devices

    Forward all read/write operations to PeripheralCharacteristic wrapper
    because initially access to characteristic has been implemented there.

    Could be interesting in the future to implement all these operations here
    and to forward from characteristic wrapper to characteristic value wrapper
    because it makes more sense.

    Anyway, this code just works but from an architectural point-of-view is
    a bit crappy.
    """

    def __init__(self, char_value, gatt):
        CharacteristicValue.__init__(self, char_value.uuid, char_value.handle, char_value.value, char_value.characteristic)
        RemoteAttribute.__init__(self, char_value.handle, gatt)

    @property
    def value(self) -> bytes:
        """Transparent characteristic read.

        :return bytes: Characteristic value
        """
        value = super().read()

        # Update model's cached value
        if Attribute.value.fset:
            Attribute.value.fset(self, value)

        return value

    @value.setter
    def value(self, value: bytes):
        """Transparent characteristic write.

        :param bytes val: Value to write into this characteristic
        """
        # Write value
        self.write(value)

        # Update model's cached value
        if Attribute.value.fset:
            Attribute.value.fset(self, value)


class PeripheralCharacteristic(Characteristic, RemoteAttribute):
    """Characteristic wrapper for peripheral devices

    Instruments gatt to read/write a remote characteristic.
    """
    def __init__(self, characteristic, gatt):
        # Populate this characteristic attribute
        Characteristic.__init__(self, characteristic.uuid, characteristic.handle,
                         characteristic.end_handle, characteristic.value,
                         characteristic.properties, characteristic.security)

        # Wrap descriptors and add them to our list of descriptors
        for desc in characteristic.descriptors():
            self.add_descriptor(PeripheralCharacteristicDescriptor(desc, gatt))

        # Initialize the remote attribute interface
        RemoteAttribute.__init__(self,characteristic.value_handle, gatt)

    def get_descriptor(self, desc_type: Union[UUID, Type[Descriptor]]):
        """Retrieve a specific descriptor from those associated with this characteristic."""
        result = super().get_descriptor(desc_type)
        # Not found? return None.
        if result is None:
            return None

        # Wrap descriptor if needed.
        if not isinstance(result, PeripheralCharacteristicDescriptor):
            return PeripheralCharacteristicDescriptor(result, self.gatt)
        return result

    @property
    def value(self) -> bytes:
        """Characteristic's value"""
        # Read value from characteristic
        value = super().read()

        # Update the underlying attribute value
        if Attribute.value.fset:
            Attribute.value.fset(self.value_attr, value)
        return value

    @value.setter
    def value(self, value: bytes):
        # Write new value into characteristic
        self.write(value)

        # Update model's cached value
        if Attribute.value.fset:
            Attribute.value.fset(self.value_attr, value)

    @property
    def cached_value(self) -> bytes:
        if Attribute.value.fget:
            return Attribute.value.fget(self.value_attr)
        return b''

    def read(self, offset: int = 0) -> bytes:
        """Read characteristic value.

        :param offset: If specified, start reading at this offset.
        :type  offset: int
        :return: Content of the characterstic's value
        :rtype:  bytes
        """
        return super().read(offset=offset)

    def write(self, value: bytes, without_response: bool = False) -> bool:
        """Set characteristic value

        If characteristic is only writeable without response, use a write command
        rather than a write request. Otherwise, use a write request. If a characteristic
        has both write and write without response properties, `without_response` must be
        set to True to use a write command.

        :param value: Value to write into the characteristic
        :type value: bytes
        :param without_response: Send a GATT write command instead of a GATT write
                                 if set to `True`
        :return: `True` on successful write, `False` otherwise
        :rtype: bool
        """
        # If characteristic is only writeable without response, force without_response to True.
        access_mask = Properties.WRITE_WITHOUT_RESPONSE | Properties.WRITE
        if (self.properties & access_mask) == Properties.WRITE_WITHOUT_RESPONSE:
            without_response = True

        return super().write(value, without_response)

    def subscribe(self, notification=False, indication=False, callback=None):
        """Subscribe for notification/indication.

        :param bool notification: If set, subscribe for notification
        :param bool indication: If set, subscribe for indication (cannot be used
                                when notification is set)
        :param callable callback: Callback function to be called on
                                  indication/notification event
        :return bool: True if subscription has successfully been performed, False otherwise.
        """
        # wrap our callback to provide more details about the concerned
        # characteristic
        def wrapped_cb(_, value, indication=False):
            if callback is not None:
                callback(
                    self,
                    value,
                    indication=indication
                )

        if notification:
            # Look for CCCD
            desc = self.get_descriptor(UUID(0x2902))
            if desc is not None:
                # Register our callback
                if callback is not None:
                    self.gatt.register_notification_callback(
                        self.value_handle,
                        wrapped_cb
                    )

                # Enable notification
                desc.write(bytes([0x01, 0x00]))

                return True

            # No CCCD, cannot subscribe
            logger.debug("No CCC descriptor, cannot subscribe to charac. %s", self.uuid)
            return False

        if indication:
            # Look for CCCD
            desc = self.get_descriptor(UUID(0x2902))
            if desc is not None:
                # Register our callback
                if callback is not None:
                    self.gatt.register_notification_callback(
                        self.value_handle,
                        wrapped_cb
                    )

                # Enable indication
                desc.write(bytes([0x02, 0x00]))

                return True

            # No CCCD, cannot subscribe for indications
            logger.debug("No CCC descriptor, cannot subscribe to charac. %s", self.uuid)
            return False

        # No indication or notification subscription required
        return False

    def unsubscribe(self):
        """Unsubscribe from this characteristic.
        """
        # Look for CCCD
        desc = self.get_descriptor(UUID(0x2902))

        if desc is not None:
            # Disable notification/indication
            desc.write(bytes([0x00, 0x00]))

            # Unregister our callback
            self.gatt.unregister_notification_callback(
                self.value_handle
            )
            return True

        # No descriptor found, cannot unsubscribe
        logger.debug("No CCC descriptor, cannot unsubscribe from charac. %s", self.uuid)
        return False


class PeripheralService(Service):
    """Service wrapper for peripheral devices
    """

    def __init__(self, service, gatt):
        """Initialize a peripheral service from discovered GATT service."""
        self.__gatt = gatt
        super().__init__(service.type_uuid, service.uuid, service.handle, service.end_handle)

        # Copy characteristics and wrap each of them into a `PeripheralCharacteristic` object.
        for charac in service.characteristics():
            self.add_characteristic(PeripheralCharacteristic(charac, self.__gatt))

        # Copy included services
        for inc_service in service.included_services():
            self.add_included_service(inc_service)

    def __iter__(self) -> Iterator[UUID]:
        """Iterator over the discovered characteristics."""
        for charac in self.characteristics():
            yield charac.uuid

    def __getitem__(self, key) -> PeripheralCharacteristic:
        """
        Retrieve a :class:`whad.ble.profile.device.PeripheralCharacteristic` object from
        its corresponding UUID.

        This special method simplifies operations based on this :class:`whad.ble.profile.device.PeripheralService`
        class, like checking the presence of a characteristing in the discovered service or simply getting an object
        representing this characteristic.

        To check if a specific characteristic with UUID `2A00` exists, one may simply use Python's `in` operator:

        ```python
        # From the 16-bit integer value corresponding to the characteristic UUID:
        if 0x2A00 in service:
            print("Characteristic with UUID 2A00 does exist.")

        # Or a string containing the UUID value
        if '2A00' in service:
            print("Characteristic with UUID 2A00 does exist.")

        # Or simply with an instance of UUID
        if UUID('2A00') in service:
            print("Characteristic with UUID 2A00 does exist.")

        ```

        To access a specific characteristic and retrieve the corresponding
        :class:`whad.ble.profile.device.PeripheralCharacteristic` object:

        ```python
        char = service[UUID('1800')]
        ```
        """
        # Key must be a valid UUID
        try:
            # Check service UUID
            if not isinstance(key, UUID):
                char_uuid = UUID(key)
            else:
                char_uuid = key

            # Retrieve object, if it does exist.
            char = self.char(char_uuid)
            if char is None:
                raise IndexError()

            # Found
            return char
        except InvalidUUIDException as uuid_err:
            raise IndexError() from uuid_err

    def read_characteristic_by_uuid(self, uuid) -> Optional[bytes]:
        """Read a characteristic belonging to this service identified by its UUID, using a GATT ReadByType
        procedure as defined in the specification (Vol 3, Part G, Section 4.8.2).

        This method can be called at any time, even if the target device's attributes have not been discovered
        yet by calling the :py:meth:`~.discover` method.

        :param uuid: Characteristic UUID
        :type  uuid: UUID
        :return bytes: Characteristic value
        """
        values = self.__gatt.read_characteristic_by_uuid(
            uuid,
            self.handle,
            self.end_handle
        )
        if len(values) > 0:
            return values[0].value
        else:
            return None

    def char(self, uuid: Union[str, UUID]) -> Optional[PeripheralCharacteristic]:
        """Look for a specific characteristic belonging to this service, identified by its UUID.

        :param uuid: Characteristic UUID
        :type  uuid: UUID, str
        :return: Found characteristic if any, `None` otherwise.
        :rtype: PeripheralCharacteristic
        :raise: InvalidUUIDException
        """
        # Convert to UUID if str is provided
        if isinstance(uuid, str):
            uuid = UUID(uuid)

        # Search for matching characteristic
        for charac in self.characteristics():
            if charac.uuid == uuid:
                return charac

        # Not found
        return None


    def get_characteristic(self, uuid: UUID) -> Optional[PeripheralCharacteristic]:
        """Look for a specific characteristic belonging to this service, identified by its UUID.

        :param uuid: Characteristic UUID
        :type  uuid: UUID
        :return: Found characteristic if any, `None` otherwise.
        :rtype: PeripheralCharacteristic

        .. deprecated:: 1.3.0
            This method has been superseeded by :py:meth:`~.char` starting from version 1.3.0,
            in a effort to make WHAD's API simpler and easier to use.
        """
        return self.char(uuid)


class PeripheralDevice(GenericProfile):
    """GATT client wrapper representing a remote device.

    This class is used to wrap a device model used in a gatt client
    in order to provide easy-to-use methods to access its services,
    characteristics and descriptors.
    """

    def __init__(self,  central, gatt_client, conn_handle, from_json=None):
        """Create a peripheral device from a Central and a GATT client.

        :param  central:        Central instance used to connect to a target device.
        :type   central:        :class:`whad.ble.connector.central.Central`
        :param  gatt_client:    GATT client connected to a target device.
        :type   gatt_client:    :class:`whad.ble.stack.gatt.GattClient`
        :param  conn_handle:    Current connection handle.
        :type   conn_handle:    int
        :param  from_json:      GATT profile (JSON) to be used when instanciating
                                the underlying GattProfile.
        :type   from_json:      str, optional
        """
        self.__gatt = gatt_client
        self.__smp = gatt_client.smp
        self.__ll = gatt_client.get_layer('ll')
        self.__conn_handle = conn_handle
        self.__central = central
        self.__disconnect_cb = None
        super().__init__(from_json=from_json)


    @property
    def conn_handle(self) -> int:
        """Current connection handle.
        """
        return self.__conn_handle

    def __iter__(self) -> Iterator[UUID]:
        """Iterator for services's UUIDs."""
        for service in self.services():
            yield service.uuid

    def __getitem__(self, key):
        """
        Retrieve a :class:`whad.ble.profile.device.PeripheralService` object from
        its corresponding UUID.

        This special method simplifies operations based on this :class:`whad.ble.profile.device.PeripheralDevice`
        class, like checking the presence of a service in the discovered atrributes or simply getting an object
        representing this service.

        To check if a specific service with UUID `1800` exists, one may simply use Python's `in` operator:

        ```python
        # From the 16-bit integer value corresponding to the service UUID:
        if 0x1800 in device:
            print("Service with UUID 1800 does exist.")

        # Or a string containing the UUID value
        if '1800' in device:
            print("Service with UUID 1800 does exist.")

        # Or simply with an instance of UUID
        if UUID('1800') in device:
            print("Service with UUID 1800 does exist.")

        ```

        To access a specific service and retrieve the corresponding :class:`whad.ble.profile.device.PeripheralService`
        object:

        ```python
        service = device[UUID('1800')]
        ```
        """
        # Key must be a valid UUID
        try:
            # Check service UUID
            if not isinstance(key, UUID):
                service_uuid = UUID(key)
            else:
                service_uuid = key

            # Retrieve object, if it does exist.
            service = self.service(service_uuid)
            if service is None:
                raise IndexError()

            # Found
            return service
        except InvalidUUIDException as uuid_err:
            raise IndexError() from uuid_err


    def start_encryption(self):
        """Start encryption procedure for BLE peripheral
        """
        security_database = self.__smp.security_database


        crypto_material = security_database.get(address=self.__central.target_peer)
        conn_handle = self.__smp.get_layer('l2cap').state.conn_handle
        if crypto_material is not None and crypto_material.has_ltk():
            self.__ll.start_encryption(
                conn_handle,
                unpack('>Q', crypto_material.ltk.rand)[0],
                crypto_material.ltk.ediv
            )

    def pairing(self, pairing=None):
        """Trigger a pairing according to provided parameters.
        Default parameters will be used if pairing parameter is None.
        """
        if not self.__smp.initiate_pairing(parameters=pairing):
            return False

        while not self.__smp.is_pairing_done():
            sleep(0.1)
            if self.__smp.is_pairing_failed():
                return False

        self.__smp.reset_state()
        return True

    def set_disconnect_cb(self, callback):
        """Set disconnection callback.

        :param callback:    Callback function to call on disconnection.
        :type   callback:   callable
        """
        self.__disconnect_cb = callback


    def set_mtu(self, mtu: int):
        """Update connection MTU.

        :param  mtu:    ATT MTU to use for this connection.
        :type   mtu:    int
        :return:        Remote device MTU.
        :rtype: int
        """
        return self.__gatt.set_mtu(mtu)


    def disconnect(self):
        """Terminate the connection to this device
        """
        # Ask associated central to disconnect this peripheral device.
        self.__central.disconnect(self.__conn_handle)


    def discover(self, include_values: bool = False):
        """Discovers services, characteristics and descriptors.

        This method must be called before accessing any service or characteristic,
        as it is required to retrieve the corresponding GATT handles.
        """
        # Discover
        self.__gatt.discover(save_values=include_values)

    def discover_primary_services(self, start: int = 1):
        """Discovers primary services only, starting from handle `start`.
        Discovered services are added to the current GATT profile and can be listed
        with :py:meth:`.services()`.

        :param start: Discover services with handle in range [`start`, 0xFFFF]
        :type  start: int
        """
        self.__gatt.discover_primary_services(start)

    def discovery_service_characteristics(self, service: Service, values: bool = False,
                                          start: int = 1) -> Iterator[Characteristic]:
        """Discovers characteristics that belong to a specific service.

        :param service: Service to discover characteristics from
        :type  service: Service
        :param values: When set to `True`, characteristics' value will be read and loaded into their
                       corresponding CharacteristicValue's value
        :type  values: bool, optional
        :param  start: Handle value used as the starting value for this discovery procedure
        :type   start: int, optional
        :return: Iterator over discovered characteristics
        :rtype: Iterator[Characteristic]
        """
        yield from self.__gatt.discovery_service_characteristics(service, save_values=values, start=start)

    def find_service_by_uuid(self, uuid: UUID) -> Optional[Service]:
        """Find service by its UUID

        :param  uuid:   Characteristic UUID
        :type   uuid:   :class:`whad.ble.profile.attribute.UUID`
        :return:        PeripheralService: An instance of PeripheralService if
                        service has been found, None otherwise.
        :rtype: :class:`whad.ble.profile.device.PeripheralService`
        """
        service = self.__gatt.discover_primary_service_by_uuid(uuid)
        if service is not None:
            return PeripheralService(
                service,
                self.__gatt
            )

        # Not found
        return None

    def char(self, uuid: Union[str, UUID], service: Optional[Union[str, UUID]] = None) -> Optional[PeripheralCharacteristic]:
        """Retrieve a characteristic by its UUID. If more than one characteristic is found,
        returns the first match.

        Search can be narrowed to a specific service if the `service` parameter is set.

        :param uuid: Characteristic's UUID
        :type  uuid: :class:`whad.ble.profile.attribute.UUID`, str
        :type  uuid: :class:`str`
        :param service: Service's UUID
        :type  service: :class:`whad.ble.profile.attribute.UUID`, :class:`str`, optional
        :return:     First matching characteristic, `None` if not found
        :rtype:      PeripheralCharacteristic
        :raise:      InvalidUUIDException
        """
        # If UUID is a string, convert to the corresponding UUID object
        if isinstance(uuid, str):
            uuid = UUID(uuid)

        # Search for characteristic
        if service is None:
            for s in self.services():
                for charac in s.characteristics():
                    if charac.uuid == uuid:
                        return charac
        else:
            # Convert service UUID if provided as a string
            if isinstance(service, str):
                service_uuid = UUID(service)
            else:
                service_uuid = service

            s = self.service(service_uuid)
            if s is not None:
                return s.char(uuid)

        # Not found
        return None


    def find_characteristics_by_uuid(self, uuid: UUID) -> List[PeripheralCharacteristic]:
        """Find characteristic by its UUID

        :param  uuid:   Characteristic UUID
        :type   uuid:   :class:`whad.ble.profile.attribute.UUID`
        :return:        PeripheralCharacteristic: An instance of PeripheralCharacteristic
                        if characteristic has been found, None otherwise.
        :rtype: :class:`whad.ble.profile.device.PeripheralCharacteristic`
        """
        characs = self.__gatt.find_characteristics_by_uuid(uuid)
        return [PeripheralCharacteristic(charac, self.__gatt) for charac in characs]

    def find_object_by_handle(self, handle) -> Optional[Attribute]:
        """Find an existing object (service, attribute, descriptor) based on its handle,
        it known from the underlying GenericProfile.

        :param  handle: Object handle
        :type   handle: int
        :return:        Characteristic, characteristic value or service
        :rtype:         :class:`whad.ble.profile.device.PeripheralCharacteristic`,
                        :class:`whad.ble.profile.device.PeripheralCharacteristicValue`,
                        :class:`whad.ble.profile.device.PeripheralService`
        """
        # Search for object
        obj = super().find_object_by_handle(handle)

        # If object has been found, make sure we wrap it in the corresponding class
        # to allow user to read and write from/into this attribute over the existing
        # connection.

        if isinstance(obj, Characteristic):
            # Wrap characteristic if required
            if not isinstance(obj, PeripheralCharacteristic):
                return PeripheralCharacteristic(obj, self.__gatt)
            return obj

        if isinstance(obj, Service):
            # Wrap service if required
            if not isinstance(obj, PeripheralService):
                return PeripheralService(obj, self.__gatt)
            return obj

        if isinstance(obj, CharacteristicValue):
            # Wrap characteristic value if required
            if not isinstance(obj, PeripheralCharacteristicValue):
                return PeripheralCharacteristicValue(
                    obj,
                    self.__gatt
                )
            return obj

        if isinstance(obj, Descriptor):
            # wrap descriptor if required
            if not isinstance(obj, PeripheralCharacteristicDescriptor):
                return PeripheralCharacteristicDescriptor(
                    obj,
                    self.__gatt
                )
            return obj

        # Not found
        return None

    def get_characteristic(self, service_uuid: UUID, charac_uuid: UUID):
        """Get a PeripheralCharacteristic object representing a characteristic
        defined by the given service UUID and characteristic UUID.

        :param  service_uuid:   Service UUID
        :type   service_uuid:   :class:`whad.ble.profile.attribute.UUID`
        :param  charac_uuid:    Characteristic UUID
        :type   charac_uuid:    :class:`whad.ble.profile.attribute.UUID`
        :return:                PeripheralCharacteristic object on success, None if not found.
        :rtype: :class:`whad.ble.profile.device.PeripheralCharacteristic`
        """
        service = self.get_service(service_uuid)
        if service is not None:
            return service.get_characteristic(charac_uuid)
        return None

    def has(self, interface: Type[PT]) -> bool:
        """Check if device exposes a specific service interface."""
        if issubclass(interface, PrimaryService):
            service_model = interface()

            # Raise an exception if service's UUID is undefined
            if service_model.uuid is None:
                return False

            # Check if we have such service
            remote_serv = self.service(service_model.uuid)
            if remote_serv is None:
                return False

            # Check if we have all the required characteristics
            for char in service_model.characteristics():
                # Make sure the service's characteristic has an UUID
                if char.uuid is None:
                    return False

                # Search for mandatory characteristics
                if remote_serv.char(char.uuid) is None:
                    if char.required:
                        return False

            # success if we loaded at least one service
            return True

        # Failure.
        return False


    def query(self, interface: Type[PT]) -> PT:
        """Dynamically load a pluggable service into this device definition."""
        if issubclass(interface, PrimaryService):
            # Create an instance of our associated primary service class. We will later
            # inject our own characteristics into it.
            service = interface()
            if service.uuid is not None:
                # Retrieve the remote service based on this UUID
                remote_service = self.service(service.uuid)
                if remote_service is not None:

                    # Loop on characteristics defined in this service,
                    # search for them in our attribute DB and inject
                    # our wrapped objects into our remote service with
                    # the corresponding aliases
                    for char in service.characteristics():
                        # Make sure the service's characteristic has an UUID
                        if char.uuid is None:
                            raise ServiceNotFound()

                        # Query the corresponding characteristic object
                        # and inject it into our pluggable instance.
                        remote_char = remote_service.char(char.uuid)
                        if remote_char is not None and char.alias:
                            setattr(service, char.alias, remote_char)
                        elif char.required:
                            raise ServiceNotFound()
                        elif char.alias:
                            # Inject the characteristic but set it to None (undefined)
                            setattr(service, char.alias, None)

                    # Return the populated service interface instance
                    return service

        # Pluggable cannot be loaded.
        raise ServiceNotFound()

    def service(self, uuid: Union[str, UUID]):
        """Retrieve a PeripheralService object given its UUID.

        :param  uuid:       Service UUID
        :type   uuid:       :class:`whad.ble.profile.attribute.UUID`
        :type   uuid:       str
        :return:            Corresponding PeripheralService object if found, None otherwise.
        :rtype: :class:`whad.ble.profile.device.PeripheralService`
        :raise: InvalidUUIDException
        """
        # If a string is provided as UUID, convert it to the corresponding
        # UUID object. This could raise an InvalidUUIDException.
        if isinstance(uuid, str):
            uuid = UUID(uuid)

        # Search for a service matching the given UUID
        for service in self.services():
            if service.uuid == uuid:
                if not isinstance(service, PeripheralService):
                    return PeripheralService(service, self.__gatt)
                return service
        return None

    def get_service(self, uuid):
        """Retrieve a PeripheralService object given its UUID.

        :param  uuid:       Service UUID
        :type   uuid:       :class:`whad.ble.profile.attribute.UUID`
        :return:            Corresponding PeripheralService object if found, None otherwise.
        :rtype: :class:`whad.ble.profile.device.PeripheralService`

        .. deprecated:: 1.3.0
            The new :meth:`~whad.ble.profule.device.PeripheralDevice.service` method shall be used to
            retrieve a :class:`~whad.ble.profile.device.PeripheralService` object representing a service
            identified by a given UUID.
        """
        return self.service(uuid)

    def write(self, handle, value):
        """Perform a write operation on an attribute based on its handle.

        This method allows to interact with characteristics and descriptors without
        having performing a GATT services and characteristics discovery. One just need
        to specify the handle corresponding to a characteristic value or descriptor and the
        value to write to it, and our GATT stack will handle it.

        Note that there is absolutely no check on corresponding characteristic permissions
        (meaning you can try to write on a read-only characteristic value) and that this
        method may raise exceptions due to potential GATT errors the remote device may
        return.

        :param  handle: Characteristic or descriptor handle to write.
        :type   handle: int
        :param  value:  Bytes to write into this characteristic.
        :type   value:  bytes
        """
        return self.__gatt.write(handle, value)


    def write_command(self, handle, value):
        """Perform a write command operation (no write response will be sent) on
        an attribute based on its handle.

        This method allows to interact with characteristics and descriptors without
        having performing a GATT services and characteristics discovery. One just need
        to specify the handle corresponding to a characteristic value or descriptor and the
        value to write to it, and our GATT stack will handle it.

        Note that there is absolutely no check on corresponding characteristic permissions
        (meaning you can try to write on a read-only characteristic value) and that this
        method may raise exceptions due to potential GATT errors the remote device may
        return.

        :param  handle: Characteristic or descriptor handle to write.
        :type   handle: int
        :param  value:  Bytes to write into this characteristic.
        :type   value:  bytes
        """
        return self.__gatt.write_command(handle, value)

    def read(self, handle, offset=None, long=False):
        """Perform a read operation on an attribute based on its handle.

        This method allows to interact with characteristics and descriptors without
        having performing a GATT services and characteristics discovery. One just need
        to specify the handle corresponding to a characteristic value or descriptor
        and our GATT stack will handle it.

        Note that there is absolutely no check on corresponding characteristic permissions
        (meaning you can try to read from a write-only characteristic value) and that this
        method may raise exceptions due to potential GATT errors the remote device may
        return.

        :param  handle: Characteristic or descriptor handle.
        :type   handle: int
        :param  offset: Offset applied when reading data from characteristic or
                        descriptor (default: 0).
        :type   offset: int, optional
        :param  long:   use GATT long read procedure if set to True (default: False)
        :type   long:   bool, optional
        :return:        Content of the characteristic or descriptor.
        :rtype: bytes
        """
        if not long:
            if offset is None:
                return self.__gatt.read(handle)

            # Use provided offset
            return self.__gatt.read_blob(handle, offset=offset)

        # Read long
        return self.__gatt.read_long(handle)

    def services(self) -> Iterator[PeripheralService]:
        """Iterate over the device's GATT services.

        :return: An iterator that can be used to iterate over services.
        :rtype: Iterator
        """
        for service in super().services():
            if not isinstance(service, PeripheralService):
                yield PeripheralService(
                    service,
                    self.__gatt
                )
            else:
                yield service

    def on_disconnect(self, conn_handle):
        """Disconnection callback

        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        """
        logger.debug("PeripheralDevice has disconnected (conn. handle: %d)", conn_handle)
        if self.__disconnect_cb is not None:
            self.__disconnect_cb()

    def on_mtu_changed(self, mtu: int):
        """MTU change callback

        :param mtu: New MTU value
        :type  mtu: int
        """
        logger.debug("PeripheralDevice: MTU has been changed to %d", mtu)
