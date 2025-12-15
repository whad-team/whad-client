"""
BLE GATT Service Model
======================
"""
import logging
from typing import Optional
from struct import pack

from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.profile.attribute import Attribute, UUID, get_uuid_alias
from whad.ble.profile.characteristic import Characteristic
from whad.ble.utils.clues import CluesDb

logger = logging.getLogger(__name__)

class Service(Attribute):
    """GATT service attribute
    """

    def __init__(self, type_uuid: UUID, uuid: UUID, handle: int = 0, end_handle: int = 0, **children):
        # Create our base attribute with type UUID, handle and value.
        super().__init__(uuid=type_uuid,handle=handle, value=uuid.to_bytes())

        # Set service UUID
        self.__service_uuid = uuid

        # Characteristics contained in service.
        self.__characteristics = []

        # Secondary services included in this service.
        self.__included_services = []

        # If handle is not 0, then we are not in template mode and we set this service without considering any
        # template characteristics or included services.
        if handle > 0:
            # Set characteristic end handle
            self.handle = handle
            self.__end_handle = end_handle
        else:
            # Template mode, we enumerate the class attributes to find template characteristics.
            self.__end_handle = 0
            for name, obj in self.inspect(Characteristic, Service):
                if isinstance(obj, Characteristic):
                    # For each template characteristic, we build it and replace the template object
                    # with this new one (but the template object is still in class definition).
                    charac = obj.build()
                    charac.service = self
                    charac.alias = name
                    self.add_characteristic(charac)
                    setattr(self, name, charac)
                elif isinstance(obj, Service):
                    service = obj.build()
                    self.add_included_service(service)

            # Add defined children (characteristic & include service)
            for name, obj in children.items():
                if isinstance(obj, Characteristic):
                    charac = obj.build()
                    charac.service = self
                    charac.alias = name
                    self.add_characteristic(charac)
                    setattr(self, name, charac)
                elif isinstance(obj, Service):
                    service = obj.build()
                    self.add_included_service(service)

    @property
    def uuid(self) -> UUID:
        """Service UUID
        """
        return self.__service_uuid

    @Attribute.handle.setter
    def handle(self, new_handle: int):
        """Overwrite `Attribute` handle setter.
        """
        # Update service handle
        Attribute.handle.fset(self, new_handle)

        # Update the underlying characteristics
        char_handle = new_handle
        for characteristic in self.__characteristics:
            characteristic.handle = char_handle + 1
            char_handle = characteristic.end_handle

        # Update service end_handle value
        self.__end_handle = char_handle

    @property
    def end_handle(self) -> int:
        """End handle
        """
        return self.__end_handle

    @end_handle.setter
    def end_handle(self, value: int):
        """Set end handle
        """
        self.__end_handle = value

    @property
    def name(self) -> str:
        """Readable service name
        """
        # Search in Bluetooth known UUIDs
        alias = get_uuid_alias(self.__service_uuid)
        if alias is not None:
            return f"{alias} (0x{self.__service_uuid})"

        # Search in collaborative CLUES database
        alias = CluesDb.get_uuid_alias(self.__service_uuid)
        if alias is not None:
            if self.__service_uuid.type == UUID.TYPE_16:
                return f"{alias} (0x{self.__service_uuid})"
            else:
                return f"{alias} ({self.__service_uuid})"

        # Default name
        return str(self.__service_uuid)

    def payload(self):
        """Return service UUID as bytes
        """
        return self.__service_uuid.packed

    def add_characteristic(self, characteristic):
        """Add characteristic, update end handle
        """
        # If characteristic's handle is 0, we define its handle before
        # adding it into our list of characteristics.
        if characteristic.handle == 0:
            characteristic.handle = self.end_handle + 1

        # Add this characteristic into our list
        self.__characteristics.append(characteristic)

        # Update our end handle
        self.__end_handle = max(characteristic.end_handle, self.__end_handle)

    def remove_characteristic(self, characteristic):
        """Remove a specific characteristic
        """
        if isinstance(characteristic, UUID):
            # Look for characteristic and remove it if found
            for charac in self.__characteristics:
                if charac.uuid == characteristic:
                    self.__characteristics.remove(charac)
                    break
        elif isinstance(characteristic, Characteristic):
            # Look for characteristic object
            if characteristic in self.__characteristics:
                self.__characteristics.remove(characteristic)

        # Update characteristic handles
        char_handle = self.handle
        for charac in self.__characteristics:
            charac.handle = char_handle + 1
            char_handle = charac.end_handle

        # Update service end_handle value
        self.__end_handle = char_handle

    def characteristics(self):
        """Enumerate characteristics
        """
        yield from self.__characteristics

    def get_characteristic(self, uuid):
        """Get characteristic by UUID
        """
        for charac in self.__characteristics:
            if charac.uuid == uuid:
                return charac
        return None

    def add_included_service(self, included_service):
        """Add include service definition, update end handle
        """
        # Set included service handle if not already set.
        if included_service.handle == 0:
            included_service.handle = self.end_handle + 1

        # Add included service into our list.
        self.__included_services.append(included_service)

        # Update end handle
        self.__end_handle = max(included_service.handle, self.__end_handle)

    def remove_include_service(self, included_service):
        """Remove a specific characteristic
        """
        if isinstance(included_service, UUID):
            # Look for characteristic and remove it if found
            for inc_service in self.__included_services:
                if inc_service.uuid == included_service:
                    self.__included_services.remove(inc_service)
                    break
        elif isinstance(included_service, IncludeService):
            # Look for characteristic object
            if included_service in self.__included_services:
                self.__included_services.remove(included_service)

        # Update included services and characteristic handles
        char_handle = self.handle
        for inc_service in self.__included_services:
            inc_service.handle = char_handle + 1
            char_handle = inc_service.handle
        for characteristic in self.__characteristics:
            characteristic.handle = char_handle + 1
            char_handle = characteristic.end_handle

        # Update service end_handle value
        self.__end_handle = char_handle

    def included_services(self):
        """Enumerate included services
        """
        yield from self.__included_services

    @classmethod
    def _build(cls, instance):
        """Build a service based on the current object (template)."""
        assert instance.handle == 0

        # Create a basic service with same properties.
        service = cls(instance.uuid, instance.type_uuid, 0, 0)

        # Clone and add characteristics.
        for charac in instance.characteristics():
            service.add_characteristic(charac.build())
            if charac.alias is not None:
                setattr(service, charac.alias, charac)

        # Return our cloned service
        return service

    def build(self):
        """Build a new service based on current template class."""
        return self.__class__._build(self)

class PrimaryService(Service):
    """Primary service attribute.

    This attribute has a type UUID of 0x2800.
    """

    def __init__(self, uuid, handle: int = 0, end_handle: int = 0, **characteristics):
        super().__init__( UUID(0x2800), uuid, handle=handle, end_handle=end_handle, **characteristics)


    @classmethod
    def _build(cls, instance):
        """Clone service."""
        # Create a basic service with same properties.
        service = cls(instance.uuid, 0, 0)

        # Clone and add characteristics.
        for charac in instance.characteristics():
            charac_obj = charac.build()
            service.add_characteristic(charac_obj)
            if charac.alias:
                setattr(service, charac.alias, charac_obj)

        # Clone and add included services.
        for inc_service in instance.included_services():
            service.add_included_service(inc_service.build())

        # Return our cloned service
        return service

class StandardService(PrimaryService):
    """Standard service class.

    Service UUID shall be set as a property in every class inheriting from this
    service.
    """

    _uuid = None

    def __init__(self, handle: int = 0, end_handle: int = 0, **characteristics):
        super().__init__(self._uuid, handle, end_handle, **characteristics)

    @classmethod
    def _build(cls, instance):
        """Clone service."""
        # Create a basic service with same properties.
        service = cls(0, 0)

        # Return our cloned service
        return service

class SecondaryService(Service):
    """Secondary service attribute.

    This attribute has a type UUID of 0x2801.
    """

    def __init__(self, uuid, handle: int = 0):
        super().__init__( UUID(0x2801), uuid, handle=handle)

    @classmethod
    def _build(cls, instance):
        """Clone service."""
        # Create a basic service with same properties.
        service = cls(instance.uuid, 0)

        # Clone and add characteristics.
        for charac in instance.characteristics():
            service.add_characteristic(charac)
            if charac.alias:
                setattr(service, charac.alias, charac)

        # Return our cloned service
        return service

class IncludeService(Attribute):
    """IncludeService Attribute class

    This class stores the information related to an included service:

    - the included service UUID (16-bit or 128-bit UUID)
    - the start and end handles of the said included service
    """

    def __init__(self, uuid, handle=0, start_handle=0, end_handle=0):
        """Initialize an included service

        :param  uuid:       Included service UUID
        :type   uuid:       UUID
        :param  handle:     Included service start handle
        :type   handle:     int
        :param  end_handle: Included service end handle
        :type   end_handle: int
        """
        self.__service_uuid = uuid
        self.__start_handle = start_handle
        self.__end_handle = end_handle
        super().__init__(UUID(0x2802), handle=handle, value=self.payload())

    @property
    def end_handle(self):
        """Return this attribute end handle

        This attribute does not belong to a group so its end handle is the same
        than its handle.
        """
        return self.handle

    @end_handle.setter
    def end_handle(self, value) -> int:
        """End handle
        """
        self.__end_handle = value

    @property
    def uuid(self) -> UUID:
        """Return the attribute type UUID.
        """
        return self.type_uuid

    @property
    def service_uuid(self) -> UUID:
        """Return the included service UUID
        """
        return self.__service_uuid

    @property
    def service_start_handle(self) -> int:
        """Return the included service start handle
        """
        return self.__start_handle

    @service_start_handle.setter
    def service_start_handle(self, value: int):
        """Service start handle setter
        """
        self.__start_handle = value

    @property
    def service_end_handle(self) -> int:
        """Return the included service end handle
        """
        return self.__end_handle

    @service_end_handle.setter
    def service_end_handle(self, value: int):
        """End handle setter
        """
        self.__end_handle = value

    @property
    def name(self) -> str:
        """Generate the description of the included service definition attribute.
        """
        # Search in Bluetooth known database
        alias = get_uuid_alias(self.__service_uuid)
        if alias is not None:
            return f"Included service {alias} (0x{self.__service_uuid})"

        # Search in collaborative CLUES database
        alias = CluesDb.get_uuid_alias(self.__service_uuid)
        if alias is not None:
            if self.__service_uuid.type == UUID.TYPE_16:
                return f"Included service {alias} (0x{self.__service_uuid})"
            else:
                return f"Included service {alias} ({self.__service_uuid})"

        # Not found, default name is UUID
        return f"Included service {self.__service_uuid}"

    def payload(self) -> bytes:
        """Return service UUID as bytes
        """
        if self.__service_uuid.type == UUID.TYPE_16:
            return pack('<HH', self.__start_handle, self.__end_handle) + self.__service_uuid.packed
        # 128-bit UUID
        return pack('<HH', self.__start_handle, self.__end_handle)

    @classmethod
    def _build(cls, instance):
        """Clone service."""
        # Create a basic service with same properties.
        return cls(instance.uuid)

