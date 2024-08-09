"""
BT Mesh domain exceptions
"""

#############
# Provisioning
#############


class UnknownParameterValueReceivedError(Exception):
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
        return (
            f"UnsupportedParameterValueReceivedError({self._parameter}, {self._value})"
        )

    def __repr__(self):
        return str(self)


class UnknownParameterValueSendError(Exception):
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
        return f"UnsupportedParameterValueSendError({self._parameter}, {self._value})"

    def __repr__(self):
        return str(self)


class FailedProvisioningReceivedError(Exception):
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
        return f"FailedProvisioningReceivedError({self._error_code})"

    def __repr__(self):
        return str(self)


class UnknownProvisioningPacketTypeError(Exception):
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
        return f"UnknownPacketTypeError({self._unknown_type})"

    def __repr__(self):
        return str(self)


class UncompatibleAlgorithmsAvailableError(Exception):
    """
    Raised when a Provisioner and a Device dont have any alg in common
    """

    def __init__(self):
        super().__init__()

    def __str__(self):
        return "UncompatibleAlgorithmsAvailableError()"

    def __repr__(self):
        return str(self)


class GenericProvisioningTimeoutError(Exception):
    """
    Raised when an expected message in Generic Provisioning layer doesnt arrive in time
    """

    def __init__(self):
        super().__init__()

    def __str__(self):
        return "GenericProvisioningTimeoutError()"

    def __repr__(self):
        return str(self)


class InvalidFrameCheckSequenceError(Exception):
    """
    Raised when a Provisioning packet has the wrong fcs in the Generic Provisioning field
    """

    def __init__(self):
        super().__init__()

    def __str__(self):
        return "InvalidFrameCheckSequenceError()"

    def __repr__(self):
        return str(self)


class UnexepectedGenericProvisioningPacketError(Exception):
    """
    Raised when a Provisioning packet has the wrong fcs in the Generic Provisioning field
    """

    def __init__(self, pkt_type):
        super().__init__()
        self._pkt_type = pkt_type

    @property
    def pkt_type(self):
        return self._pkt_type.__name__

    def __str__(self):
        return f"UnexepectedGenericProvisioningPacketError({self.pkt_type})"

    def __repr__(self):
        return str(self)


class InvalidConfirmationError(Exception):
    """
    Raised when a Confirmation value received and the one we compute do not match
    """

    def __init__(self, pkt_type):
        super().__init__()

    def __str__(self):
        return "InvalidConfirmationError()"

    def __repr__(self):
        return str(self)
