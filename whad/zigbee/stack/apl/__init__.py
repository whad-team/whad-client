from scapy.layers.zigbee import ZigbeeSecurityHeader, ZigbeeAppDataPayload
from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from whad.zigbee.stack.database import Dot15d4Database
from whad.zigbee.crypto import ApplicationSubLayerCryptoManager
from .exceptions import APSTimeoutException
from .constants import APSKeyPairSet, APSSecurityStatus, APSTrustCenterLinkKeyData, \
    APSApplicationLinkKeyData, APSNetworkKeyData
import logging

logger = logging.getLogger(__name__)



class APLService(Dot15d4Service):
    """
    This class represents an APS service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(manager, name=name, timeout_exception_class=APSTimeoutException)

class APLDataService(APSService):
    """
    APL service processing Data frames.
    """
    def __init__(self, manager):
        super().__init__(manager, name="apl_data")


class APLManagementService(APSService):
    """
    APL service processing Management operations.
    """
    def __init__(self, manager):
        super().__init__(manager, name="apl_management")


class APLManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application Layer manager (APS).
    It provides a set of services allowing to communicate with an application.

    It exposes two services providing the appropriate API.
    """
    pass
