from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from .constants import LogicalDeviceType
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

class ZDOObject:
    def __init__(self, zdo):
        self.zdo = zdo


class ZDODeviceAndServiceDiscovery(ZDOObject):
    pass

class ZDONetworkManager(ZDOObject):
    def startup(self):
        if self.zdo.logical_device_type == LogicalDeviceType.END_DEVICE:
            pass

class ZDOSecurityManager(ZDOObject):
    pass

class ZigbeeDeviceObjects(APLObject):
    def __init__(self, manager, endpoint=0):
        super().__init__(manager, name="zdo")
        self.logical_device_type = LogicalDeviceType.END_DEVICE # TODO: make it configurable
        self.security_manager = ZDOSecurityManager(self)
        self.network_manager = ZDONetworkManager(self)
        self.device_and_service_discovery = ZDODeviceAndServiceDiscovery(self)

        # initiate startup procedure
        self.network_manager.startup()

class APLManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application layer manager (APL).
    It exposes Zigbee Device Object and Application Object.
    """

    def __init__(self, aps=None):
        super().__init__(
            services={
                "zdo":ZigbeeDeviceObjects(self, endpoint=0)
            },
            upper_layer=None,
            lower_layer=aps
        )

    def get_service_by_endpoint(self, endpoint):
        for service in self._services.values():
            if service.endpoint == endpoint:
                return service
        return None

    def on_apsme_transport_key(self, source_address, standard_key_type, transport_key_data):
        pass
