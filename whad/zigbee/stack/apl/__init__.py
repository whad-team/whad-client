from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from whad.zigbee.stack.database import Dot15d4Database
from .exceptions import APLTimeoutException
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.cluster import Cluster
from whad.zigbee.stack.apl.zdo import ZigbeeDeviceObjects
from whad.zigbee.stack.mac.constants import MACAddressMode
from time import sleep
import logging

logger = logging.getLogger(__name__)

class APLManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application layer manager (APL).
    It exposes Zigbee Device Object and Application Object.
    """

    def __init__(self, aps):
        super().__init__(
            services={},
            upper_layer=None,
            lower_layer=aps
        )
        self.endpoints = {}
        self.attach_application(ZigbeeDeviceObjects(), 0)

    @property
    def aps(self):
        return self.lower_layer

    @property
    def nwk(self):
        return self.lower_layer.nwk

    def initialize(self):
        for app in self.endpoints.values():
            app.initialize()

    def start(self):
        for app in self.endpoints.values():
            app.start()

    def attach_application(self, app, endpoint):
        app.manager = self
        self._services[app.name] = app
        self.endpoints[endpoint] = app

    def get_application_by_endpoint(self, endpoint):
        if endpoint in self.endpoints:
            return self.endpoints[endpoint]
        return None

    def get_application_by_name(self, name):
        if name in self._services:
            return self._services[name]
        return None

    def send_interpan_data(self, asdu, asdu_handle=0, source_address_mode=MACAddressMode.SHORT, destination_pan_id=0xFFFF, destination_address=0xFFFF, profile_id=0, cluster_id=0):
        return self.aps.get_service("interpan").interpan_data(asdu, asdu_handle=asdu_handle, source_address_mode=source_address_mode, destination_pan_id=destination_pan_id, destination_address=destination_address, profile_id=profile_id, cluster_id=cluster_id)

    def send_data(self, asdu, destination_address_mode, destination_address, destination_endpoint, alias_address=None, alias_sequence_number=0, radius=30, security_enabled_transmission=False, use_network_key=False, acknowledged_transmission=False, fragmentation_permitted=False, include_extended_nonce=False, cluster_id=None, profile_id=None, application=None):
        selected_endpoint = None
        for endpoint, running_application in self.endpoints.items():
            if application == running_application:
                selected_endpoint = endpoint
                break
        if selected_endpoint is None:
            return False

        return self.aps.get_service("data").data(
            asdu,
            destination_address_mode,
            destination_address,
            destination_endpoint,
            profile_id,
            cluster_id,
            selected_endpoint,
            alias_address=alias_address,
            alias_sequence_number=alias_sequence_number,
            radius=radius,
            security_enabled_transmission=security_enabled_transmission,
            use_network_key=use_network_key,
            acknowledged_transmission=acknowledged_transmission,
            fragmentation_permitted=fragmentation_permitted,
            include_extended_nonce=include_extended_nonce
        )

    def on_intrp_data(self, asdu, profile_id=0, cluster_id=0, destination_pan_id=0xFFFF, destination_address=0xFFFF, source_pan_id=0xFFFF, source_address=0xFFFF, link_quality=255):
        for application in self.endpoints.values():
            if application.profile_id == profile_id:
                application.on_interpan_data(asdu, cluster_id=cluster_id, destination_pan_id=destination_pan_id, destination_address=destination_address, source_pan_id=source_pan_id, source_address=source_address, link_quality=link_quality)

    def on_apsde_data(self, asdu, destination_address, destination_address_mode, destination_endpoint, source_address, source_address_mode, source_endpoint, profile_id, cluster_id, security_status, link_quality):

        # Checks if an endpoint matches
        if destination_endpoint not in self.endpoints:
            logger.info("[apl] destination endpoint not found.")
            return

        application = self.endpoints[destination_endpoint]

        # Checks if the profile id matches the one used by the application
        if application.profile_id != profile_id:
            logger.info("[apl] profile identifier doesn't match the application profile.")
            return

        success = application.on_data(
            asdu,
            source_address,
            source_address_mode,
            cluster_id,
            security_status,
            link_quality
        )
        if not success:
            logger.info("[apl] cluster not found (cluster_id=0x{:04x}).".format(cluster_id))

    def on_apsme_transport_key(self, source_address, standard_key_type, transport_key_data):
        # Forward to ZDO
        self.get_service("zdo").on_transport_key(source_address, standard_key_type, transport_key_data)
