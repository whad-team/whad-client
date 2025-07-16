"""
Helpers for WHAD's HCI virtual device
"""
# Exceptions

from .exceptions import (
    HCIUnsupportedCommand, HCIUnsupportedFeature, HCIUnsupportedLEFeature
)

class req_cmd:
    """HCI Decorator to handle command requirements.

    Normally, we query an HCI interface to retrieve the list of its supported
    commands, following the recommended initialization procedure
    (Vol6, part D, section 1).

    We need to check that all the required commands are supported by the target
    hardware before starting a specific procedure, and this decorator provides
    a way to declare one or more required commands for a decorated method of
    HCIDevice, and blocks its execution if at least one of them is not provided
    by the target hardware.
    """

    def __init__(self, *args):
        """Save any string argument as a required HCI command.
        """
        self.__requires = []
        for arg in args:
            if isinstance(arg, str):
                self.__requires.append(arg)

    def __call__(self, method):
        """Called to decorate the actual method.
        """
        requirements = self.__requires
        def _wrap(self, *args, **kwargs):
            # check our requirements are met
            for command in requirements:
                if not self.is_cmd_supported(command):
                    raise HCIUnsupportedCommand(command)

            # If all requirements are met, forward
            return method(self, *args, **kwargs)
        return _wrap

class req_feature:
    """HCI decorator to handle command feature requirement.
    """
    def __init__(self, *args):
        self.__requires = []
        for arg in args:
            if isinstance(arg, str):
                self.__requires.append(arg)

    def __call__(self, method):
        """Called to decorate the actual method.
        """
        requirements = self.__requires
        def _wrap(self, *args, **kwargs):
            # check our requirements are met
            for feature in requirements:
                if not self.is_feature_supported(feature):
                    raise HCIUnsupportedFeature(feature)

            # If all requirements are met, forward
            return method(self, *args, **kwargs)
        return _wrap

class le_only(req_feature):
    """Requires a LE-enabled controller
    """
    def __init__(self, *args):
        super().__init__("le_supported_controller")
        self.__requires = []
        for arg in args:
            if isinstance(arg, str):
                self.__requires.append(arg)

    def __call__(self, method):
        requirements = self.__requires
        def _wrap(self, *args, **kwargs):
            # check our requirements are met
            for feature in requirements:
                if not self.is_le_feature_supported(feature):
                    raise HCIUnsupportedLEFeature(feature)

            # If all requirements are met, forward
            return method(self, *args, **kwargs)

        # Wrap with LE-enabled controller check (tested first)
        return super()(_wrap)

def compute_max_time(length: int, datarate: int) -> int:
    """Compute the maximum transmission time for a given PDU length and
    datarate.

    Prefix is 80 bits (header + CRC), suffix is some kind of security margin.
    """
    return int(((80 + length*8 + 32)/datarate)*1000000.0)

