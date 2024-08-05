"""
BT Mesh domain exceptions
"""

#############
#Provisioning
#############


class UnknownParameterValueReceived(Exception):
    """
    Raised when a parameter received in the Provisoning Layer does not exist
    """
    def __init__(self, parameter, value):
        super().__init__()
        self._parameter = parameter
        self._value = value

    @property
    def parameter(self):
        return self._parameter

    @property
    def value(self):
        return self._value

    def __str__(self):
        return f"UnsupportedParameterValueReceived({self._parameter}, {self._value})"

    def __repr__(self):
        return str(self)

class UnknownParameterValueSend(Exception):
    """
    Raised when a parameter trying to be sent in the Provisoning Layer does not exist
    """
    def __init__(self, parameter, value):
        super().__init__()
        self._parameter = parameter
        self._value = value

    @property
    def parameter(self):
        return self._parameter

    @property
    def value(self):
        return self._value

    def __str__(self):
        return f"UnsupportedParameterValueSend({self._parameter}, {self._value})"

    def __repr__(self):
        return str(self)


class FailedProvisioningReceived(Exception):
    """
    Raised when a BTMesh_Provisioning_Failed packet is received
    """
    def __init__(self, error_code):
        super().__init__()
        self._error_code = error_code

    @property
    def error_code(self):
        return self._error_code

    def __str__(self):
        return f"FailedProvisioningReceived({self._error_code})"

    def __repr__(self):
        return str(self)

class UnknownProvisioningPacketType(Exception):
    """
    Raised when an unknown packet type is received in the Provisioning Layer (should never be raised but hey for completion)
    """
    def __init__(self, unknown_type):
        super().__init__()
        self._unknown_type = unknown_type

    @property
    def unknown_type(self):
        return self._unknown_type

    def __str__(self):
        return f"UnknownPacketType({self._unknown_type})"

    def __repr__(self):
        return str(self)


class UncompatibleAlgorithmsAvailable(Exception):
    """
    Raised when a Provisioner and a Device dont have any alg in common
    """ 
    def __init__(self):
        super().__init__()

    def __str__(self):
        return "UncompatibleAlgorithmsAvailable()"

    def __repr__(self):
        return str(self)



