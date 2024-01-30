from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service

from whad.zigbee.stack.aps.exceptions import APSTimeoutException
from whad.zigbee.stack.aps.database import APSIB

import logging

logger = logging.getLogger(__name__)


class APSService(Dot15d4Service):
    """
    This class represents an APS service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(manager, name=name, timeout_exception_class=APSTimeoutException)


class APSDataService(APSService):
    """
    APS service processing Data frames.
    """
    def __init__(self, manager):
        super().__init__(manager, name="aps_data")

class APSManagementService(APSService):
    """
    APS service processing Management operations.
    """
    def __init__(self, manager):
        super().__init__(manager, name="aps_management")


class APSInterpanPseudoService(APSService):
    """
    APS pseudo service forwarding InterPAN operations.

    This service is only there to forward InterPAN to upper layers.
    """
    def __init__(self, manager):
        super().__init__(manager, name="aps_interpan")

@state(APSIB)
@alias('aps')
class APSManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application Support Sub-layer manager (APS).
    It provides a framework for application.

    It exposes two services providing the appropriate API + 1 pseudo service to forward InterPAN PDU.
    """
    def init(self):
        self.add_service("data", APSDataService(self))
        self.add_service("management", APSManagementService(self))
        self.add_service("interpan", APSInterpanPseudoService(self))
