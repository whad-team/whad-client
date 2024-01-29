class ZCLAttributePermissionDenied(Exception):
    def __init__(self):
        super().__init__()

class ZCLAttributeNotFound(Exception):
    def __init__(self):
        super().__init__()

class ZCLCommandNotFound(Exception):
    def __init__(self):
        super().__init__()
