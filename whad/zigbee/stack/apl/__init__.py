from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from .exceptions import APLTimeoutException
import logging

logger = logging.getLogger(__name__)


class APLObject(Dot15d4Service):
    """
    This class represents an APL service (named "object"), exposing a standardized API.
    """
    def __init__(self, manager, name=None, endpoint=None):
        super().__init__(manager, name=name, timeout_exception_class=APLTimeoutException)
        self.endpoint = endpoint

class ZigbeeDeviceObject(APLObject):
    def __init__(self, manager, endpoint=0):
        super().__init__(manager, name="zdo")

class APLManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application layer manager (APL).
    It exposes Zigbee Device Object and Application Object.
    """

    def __init__(self, aps=None):
        super().__init__(
            services={
                "zdo":ZigbeeDeviceObject(self, endpoint=0)
            },
            upper_layer=None,
            lower_layer=aps
        )

    def get_service_by_endpoint(self, endpoint):
        for service in self._services.values():
            if service.endpoint == endpoint:
                return service
        return None
