"""WHAD protocol message abstraction
"""
from whad.protocol.whad_pb2 import Message
from whad.hub.registry import Registry

class HubMessage(object):
    """Main class from which any ProtocolHub message derives from.
    """

    def __init__(self,  message: Message = None):
        if message is None:
            self.__msg = Message()
        else:
            self.__msg = message

    def serialize(self):
        return self.__msg.SerializeToString()

    def set_field_value(self, path: str, value):
        """Set a message field value.
        """
        path_nodes = path.split('.')
        root_node = self.message
        for node in path_nodes[:-1]:
            root_node = getattr(root_node, node)

        if hasattr(root_node, path_nodes[-1]):
            # If we are dealing with a PB array, we cannot set its value but
            # need to call extend() to add our array items.
            if isinstance(value, list):
                getattr(root_node, path_nodes[-1]).extend(value)
            else:
                setattr(root_node, path_nodes[-1], value)
        else:
            raise IndexError()
        
    def get_field_value(self, path: str):
        """Get a message field value.
        """
        # Walk to the penultimate field
        path_nodes = path.split('.')
        root_node = self.message

        for node in path_nodes[:-1]:
            if hasattr(root_node, node):
                root_node = getattr(root_node, node)
            else:
                raise IndexError()
        
        # Return the final field
        if hasattr(root_node, path_nodes[-1]):
            return getattr(root_node, path_nodes[-1])
        else:
            raise IndexError()
    
    @property
    def message(self):
        return self.__msg
    

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

class PbFieldArray(PbField):
    """Protocol buffers array field model
    """

    def __init__(self, path: str):
        """Create a PB field model for arrays.
        """
        super().__init__(path, list)

class PbFieldBool(PbField):
    """Protocol buffers bool field model
    """

    def __init__(self, path: str):
        """Create a PB field model for bools.
        """
        super().__init__(path, bool)        

class PbMessageWrapper(HubMessage):
    """Protocol Buffers message wrapper

    This class allows a mapping between its class fields (declared as `PbField`
    objects) and its underlying Protocol Buffers message object, in order to
    transparently access and updates these fields through simple parameters.
    """

    def __init__(self, message: Message = None, **kwargs):
        """Initialize a `PbMessageWrapper` object.

        This code goes through all the declared properties and finds out the
        ones based on `PbField` and then automatically binds them to the
        corresponding parameter name.
        """
        self.__pb_fields = {}

        # Create our HubMessage
        super().__init__(message=message)
        
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
        return parent_class(message=message)

'''
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
'''