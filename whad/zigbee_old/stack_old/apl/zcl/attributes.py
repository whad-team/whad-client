from whad.zigbee.stack.apl.zcl.exceptions import ZCLAttributePermissionDenied, \
    ZCLAttributeNotFound

class ZCLAttribute:
    def __init__(self, name, value=None, permissions=["read", "write"]):
        self.name = name
        self.value = value
        self.permissions = permissions

class ZCLAttributes:
    def __init__(self):
        self.attributes = {}

    def add_attribute(self, id, name, value, permissions=['read', 'write']):
        self.attributes[id] = ZCLAttribute(name=name, value=value, permissions=permissions)

    def read_by_id(self, id):
        if id in self.attributes:
            attribute = self.attributes[id]
            if "read" in attribute.permissions:
                return attribute.value
            raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def read_by_name(self, name):
        for attribute in self.attributes:
            if attribute.name == name:
                if "read" in attribute.permissions:
                    return attribute.value
                else:
                    raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def write_by_id(self, id, value):
        if id in self.attributes:
            attribute = self.attributes[id]
            if "write" in attribute.permissions:
                attribute.value = value
            raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def write_by_name(self, name, value):
        for attribute in self.attributes:
            if attribute.name == name:
                if "write" in attribute.permissions:
                    attribute.value = value
                else:
                    raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()
