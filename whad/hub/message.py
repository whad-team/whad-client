"""WHAD protocol message abstraction
"""
from typing import Any
from whad.protocol.whad_pb2 import Message
from whad.hub.registry import Registry

class PbField(object):
    """Protocol Buffers field model
    """

    def __init__(self, path: str, field_type, optional=False):
        self.__path = path
        self.__type = field_type
        self.__optional = optional

    @property
    def path(self):
        return self.__path

    @property
    def type(self):
        return self.__type

    def is_optional(self):
        """Determine if this field is optional
        """
        return self.__optional

    def update(self, message: Message):
        """Update field in protobuf message
        """
        pass

class PbFieldInt(PbField):
    """Protocol buffers integer field model
    """

    def __init__(self, path: str, optional: bool = False):
        """Create a PB field model for integer.
        """
        super().__init__(path, int, optional=optional)

class PbFieldBytes(PbField):
    """Protocol buffers bytes field model
    """

    def __init__(self, path:  str, optional: bool = False):
        """Create a PB field model for bytes
        """
        super().__init__(path, bytes, optional=optional)

class PbFieldArray(PbField):
    """Protocol buffers array field model
    """

    def __init__(self, path: str, optional: bool = False):
        """Create a PB field model for arrays.
        """
        super().__init__(path, list, optional=optional)

class PbFieldBool(PbField):
    """Protocol buffers bool field model
    """

    def __init__(self, path: str, optional: bool = False):
        """Create a PB field model for bools.
        """
        super().__init__(path, bool, optional=optional)

class PbFieldMsg(PbField):
    """Protocol buffers message field model
    """

    def __init__(self, path: str, wrap_class, optional: bool = False):
        """Create a PB field model for messages.
        """
        super().__init__(path, wrap_class, optional=optional)


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

    def set_field_value(self, field: PbField, value):
        """Set a message field value.
        """
        path_nodes = field.path.split('.')
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

    def get_field_value(self, field: PbField):
        """Get a message field value.
        """
        # Walk to the penultimate field
        path_nodes = field.path.split('.')
        root_node = self.message

        for node in path_nodes[:-1]:
            if hasattr(root_node, node):
                root_node = getattr(root_node, node)
            else:
                raise IndexError()

        # Return the final field
        if hasattr(root_node, path_nodes[-1]):
            if isinstance(field, PbFieldMsg):
                return field.type(getattr(root_node, path_nodes[-1]))
            else:
                if field.is_optional() and not root_node.HasField(path_nodes[-1]):
                    return None
                else:
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
        # Register our class with the corresponding name
        self.__registry.add_node_version(self.__version, self.__name, clazz)

        # Add to our class a category type corresponding to the registry name
        clazz.message_type = self.__registry.NAME
        clazz.message_name = self.__name
        return clazz


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
                            self.__pb_fields[prop] = prop_obj
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

    def __repr__(self):
        """Generate a string representation of our message
        """
        fields = []
        for prop_name in self.__pb_fields:
            value = self.get_field_value(self.__pb_fields[prop_name])
            if value is not None:
                fields.append((prop_name, value))

        return f"<{self.__class__.__name__} " + ', '.join(
            [f'{name}={value}' for name, value in fields]
        ) + ">"

    @classmethod
    def parse(parent_class, version: int, message: Message):
        """Parse a generic protobuf message message.
        """
        return parent_class(message=message)

class AbstractPacketMeta(type):
    """Hub packet metaclass"""
    def __instancecheck__(cls, instance):
        return cls.__subclasscheck__(type(instance))

    def __subclasscheck__(cls, subclass):
        return (hasattr(subclass, 'to_packet') and
                callable(subclass.to_packet) and
                hasattr(subclass, 'from_packet') and
                callable(subclass.from_packet))

class AbstractPacket(metaclass=AbstractPacketMeta):
    pass

class AbstractEventMeta(type):
    """Hub event metaclass
    """
    def __instancecheck__(cls, instance: Any) -> bool:
        return cls.__instancecheck__(type(instance))

    def __subclasscheck__(cls, subclass):
        return (hasattr(subclass, 'to_event') and
                callable(subclass.to_event) and
                hasattr(subclass, 'from_event') and
                callable(subclass.from_event))

class AbstractEvent(metaclass=AbstractEventMeta):
    pass
