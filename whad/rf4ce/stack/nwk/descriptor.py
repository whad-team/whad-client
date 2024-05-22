class NodeDescriptor:
    def __init__(self, address, pan_id, vendor_id = None, vendor_string="", user_string=None, device_type_list=[], profile_identifier_list=[]):
        self.address = address
        self.pan_id = pan_id
        self.vendor_id = vendor_id
        self.vendor_string = vendor_string
        self.user_string = user_string
        self.device_type_list = device_type_list
        self.profile_identifier_list = profile_identifier_list

    def __repr__(self):
        return "NodeDescriptor(address=" + hex(self.address) + ", pan_id=" + hex(self.pan_id) + ", vendor_id=" + str(self.vendor_id) + ")"
