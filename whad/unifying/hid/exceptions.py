class InvalidHIDData(Exception):
    def __init__(self, hid_data):
        self.hid_data = hid_data
        super().__init__(hid_data)
