"""WHAD Protocol Hub
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.hub.message import HubMessage
from .exceptions import UnsupportedVersionException

class Registry(object):
    """Protocol message versions registry.
    """

    VERSIONS = {}

    @classmethod
    def add_node_version(parent_class, version: int, name: str, clazz):
        """Add a specific class `clazz` to our message registry for version
        `version` with alias `name`.
        """
        # If version is unknown, create it
        if version not in Registry.VERSIONS:
            parent_class.VERSIONS[version] = {}

        # Add clazz based on provided alias for this version
        parent_class.VERSIONS[version][name] = clazz

    @classmethod
    def bound(parent_class, name: str = None, version: int = 1):
        """Retrieve the given node class `name` for version `version`.

        If there is no defined class for version N, look for a corresponding
        class in version N-1, N-2 until 0.
        """
        # Look for node class from given name and version
        if version in parent_class.VERSIONS:
            if name in parent_class.VERSIONS[version]:
                return parent_class.VERSIONS[version][name]

        if version > 1:
            # If not found for version N, look for node class in version N-1
            return parent_class.bound(name, version - 1)
            
        # If not found, raise exception
        raise UnsupportedVersionException()


class pb_bind(object):
    """Decorator to add a versioned subclass to a registry.
    """

    def __init__(self, registry: Registry, name: str, version: int):
        self.__registry = registry
        self.__name = name
        self.__version = version

    def __call__(self, clazz):
        """Decorate our class
        """
        self.__registry.add_node_version(self.__version, self.__name, clazz)
        return clazz


class PbField(object):
    """Protocol Buffers field model
    """

    def __init__(self, path: str, field_type):
        self.__path = path
        self.__type = field_type

    @property
    def path(self):
        return self.__path
    
    def update(self, message: Message):
        """Update field in protobuf message
        """
        pass

class PbFieldInt(PbField):
    """Protocol buffers integer field model
    """

    def __init__(self, path: str):
        """Create a PB field model for integer.
        """
        super().__init__(path, int)

class PbFieldBytes(PbField):
    """Protocol buffers bytes field model
    """
    
    def __init__(self, path:  str):
        """Create a PB field model for bytes
        """
        super().__init__(path, bytes)

class PbMessageWrapper(HubMessage):
    """Protocol Buffers message wrapper

    This class allows a mapping between its class fields (declared as `PbField`
    objects) and its underlying Protocol Buffers message object, in order to
    transparently access and updates these fields through simple parameters.
    """

    def __init__(self, *args, message: Message = None, **kwargs):
        """Initialize a `PbMessageWrapper` object.

        This code goes through all the declared properties and finds out the
        ones based on `PbField` and then automatically binds them to the
        corresponding parameter name.
        """
        self.__pb_fields = {}

        # Create our HubMessage
        super().__init__(1, message=message)
        
        # Browse our properties and list PB fields
        for prop in dir(self):
            if not prop.startswith('_'):
                try:
                    prop_obj = getattr(self, prop)
                    if not callable(prop_obj):
                        # check field type
                        if isinstance(prop_obj, PbField):
                            self.__pb_fields[prop] = prop_obj.path
                except AttributeError:
                    pass

        # Override message values with keyword arguments
        for message_field in kwargs:
            if message_field in self.__pb_fields:
                self.set_field_value(self.__pb_fields[message_field], kwargs[message_field])

    def __getattribute__(self, name):
        """Override the class __getattribute__ function to allow transparent
        access to protocol buffers fields for the given message and corresponding
        field paths.
        """
        if name.startswith('_'):
            return object.__getattribute__(self, name)
        elif name in self.__pb_fields:
            return self.get_field_value(self.__pb_fields[name])
        else:
            return object.__getattribute__(self, name)

    def __setattr__(self, name, value):
        """Set underlying message fields given their paths with a given value.
        """
        if name.startswith('_'):
            self.__dict__[name] = value
        elif name in self.__pb_fields:
            self.set_field_value(self.__pb_fields[name], value)

    @classmethod
    def parse(parent_class, version: int, message: Message):
        """Parse a generic protobuf message message.
        """
        return parent_class(version, message=message)


class ProtocolHub(Registry):
    """WHAD Protocol Hub class

    This class is an interface between all our Python code and the devices, that
    support all the existing versions of the WHAD protocol and handles every
    differences that exist between them in a transparent fashion.
    """

    def __init__(self, proto_version: int):
        """Instanciate a WHAD protocol hub for a specific version.
        """
        self.__version = proto_version

    @property
    def version(self) -> int:
        return self.__version
    
    def parse(self, data: bytes):
        """Parse a serialized WHAD message into an associated object.
        """
        # Use protocol buffers to parse our message
        msg = Message()
        msg.ParseFromString(bytes(data))

        # Only process generic messages
        return ProtocolHub.bound(
            msg.WhichOneof('msg'),
            self.__version).parse(self.__version, msg)

