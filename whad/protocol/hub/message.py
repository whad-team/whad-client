"""WHAD protocol message abstraction
"""
from whad.protocol.whad_pb2 import Message

class HubMessage(object):
    """Main class from which any ProtocolHub message derives from.
    """

    def __init__(self, version: int, message: Message = None):
        self.__proto_version = version
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
    def proto_version(self):
        return self.__proto_version
    
    @property
    def message(self):
        return self.__msg