from whad.zigbee.stack.apl.zcl.exceptions import ZCLAttributePermissionDenied, \
    ZCLAttributeNotFound

class ZCLAttribute:
    """
    This class represents a Zigbee Cluster Library attribute.
    """
    def __init__(self, name, value=None, permissions=["read", "write"]):
        self.name = name
        self.value = value
        self.permissions = permissions

class ZCLAttributes:
    """
    This class represents a database of Zigbee Cluster Library attributes.
    """
    def __init__(self):
        self.attributes = {}

    def add_attribute(self, id, name, value, permissions=['read', 'write']):
        """
        Adds an attribute in the database.
        """
        self.attributes[id] = ZCLAttribute(
            name=name,
            value=value,
            permissions=permissions
        )

    def read_by_id(self, id):
        """
        Reads an attribute value according to its identifier.
        """
        if id in self.attributes:
            attribute = self.attributes[id]
            if "read" in attribute.permissions:
                return attribute.value
            raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def read_by_name(self, name):
        """
        Reads an attribute value according to its name.
        """
        for attribute in self.attributes:
            if attribute.name == name:
                if "read" in attribute.permissions:
                    return attribute.value
                else:
                    raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def write_by_id(self, id, value):
        """
        Writes an attribute value according to its identifier.
        """
        if id in self.attributes:
            attribute = self.attributes[id]
            if "write" in attribute.permissions:
                attribute.value = value
            raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def write_by_name(self, name, value):
        """
        Writes an attribute value according to its name.
        """
        for attribute in self.attributes:
            if attribute.name == name:
                if "write" in attribute.permissions:
                    attribute.value = value
                else:
                    raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()
