from whad.dot15d4.stack.mac.constants import MACAddressMode
from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.zigbee.stack.apl.zdo import ZigbeeDeviceObjects
from whad.common.stack import alias, source, state # state may not be necessary ?
import logging

logger = logging.getLogger(__name__)


@alias('apl')
class APLManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application layer manager (APL).
    It exposes Zigbee Device Object and Application Object.

    Note: this component is a bit particular in ZigBee stack since it
    implements Applications instead of Services. The design adopted here
    keeps the Manager as Layer / Entry point and override Services by Applications.
    We also introduce a dictionnary mapping endpoints to applications and
    methods facilitating applications selection & management.
    """

    def init(self):
        """
        Initialize the APL layer.
        """
        # Initialize Endpoints
        self.endpoints = {}

        self.attach_application(ZigbeeDeviceObjects(), 0)

    # API to manipulate applications
    def initialize(self):
        """
        This method initializes all applications.
        """
        for app in self.endpoints.values():
            app.initialize()

    def start(self):
        """
        This method starts all applications.
        """
        for app in self.endpoints.values():
            app.start()

    def attach_application(self, app, endpoint):
        """
        This method attaches a new application to the layer on a specific endpoint.
        """
        # Provide a reference to the manager in application.
        app.manager = self

        # Add app as service
        self._services[app.name] = app
        # Add app in the endpoints dictionnary
        self.endpoints[endpoint] = app

    def get_endpoints(self):
        """
        This method returns a list of all the local endpoints.
        """
        return list(self.endpoints.keys())

    def get_application_by_endpoint(self, endpoint):
        """
        This method returns the application linked to the provided endpoint (if any).
        """
        if endpoint in self.endpoints:
            return self.endpoints[endpoint]
        return None

    def get_application_by_name(self, name):
        """
        This method returns the application linked to the provided name (if any).
        """
        if name in self._services:
            return self._services[name]
        return None

    def get_applications(self):
        """
        Iterator over all registered applications.
        """
        for application in self.endpoints.values():
            yield application


    def send_interpan_data(
                            self,
                            asdu,
                            asdu_handle=0,
                            source_address_mode=MACAddressMode.SHORT,
                            destination_pan_id=0xFFFF,
                            destination_address=0xFFFF,
                            destination_address_mode=MACAddressMode.SHORT,
                            profile_id=0,
                            cluster_id=0,
                            acknowledged_transmission=False
    ):
        """
        Transmits InterPAN PDU to the APS layer.
        """
        return self.get_layer('aps').get_service("interpan").interpan_data(
            asdu,
            asdu_handle=asdu_handle,
            source_address_mode=source_address_mode,
            destination_pan_id=destination_pan_id,
            destination_address=destination_address,
            destination_address_mode=destination_address_mode,
            profile_id=profile_id,
            cluster_id=cluster_id,
            acknowledged_transmission=acknowledged_transmission
        )

    def send_data(
                    self,
                    asdu,
                    destination_address_mode,
                    destination_address,
                    destination_endpoint,
                    alias_address=None,
                    alias_sequence_number=0,
                    radius=30,
                    security_enabled_transmission=False,
                    use_network_key=False,
                    acknowledged_transmission=False,
                    fragmentation_permitted=False,
                    include_extended_nonce=False,
                    cluster_id=None,
                    profile_id=None,
                    application=None
    ):
        """
        Transmits Data PDU to the APS layer.
        """
        selected_endpoint = None
        for endpoint, running_application in self.endpoints.items():
            if application == running_application:
                selected_endpoint = endpoint
                break
        if selected_endpoint is None:
            return False

        return self.get_layer('aps').get_service("data").data(
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

    # Callbacks processing the informations transmitted by the APS layer
    @source('aps', "INTRP-DATA")
    def on_intrp_data(
                        self,
                        asdu,
                        profile_id=0,
                        cluster_id=0,
                        destination_pan_id=0xFFFF,
                        destination_address=0xFFFF,
                        source_pan_id=0xFFFF,
                        source_address=0xFFFF,
                        link_quality=255
    ):
        """
        Callback processing InterPAN PDU transmitted by the APS layer.
        """
        # Iterate over registered applications
        for application in self.endpoints.values():
            # If we found an application matching the profile id, forwards to the cluster
            if application.profile_id == profile_id:
                application.on_interpan_data(
                    asdu,
                    cluster_id=cluster_id,
                    destination_pan_id=destination_pan_id,
                    destination_address=destination_address,
                    source_pan_id=source_pan_id,
                    source_address=source_address,
                    link_quality=link_quality
                )

    @source('aps', "APSDE-DATA")
    def on_apsde_data(
                        self,
                        asdu,
                        destination_address,
                        destination_address_mode,
                        destination_endpoint,
                        source_address,
                        source_address_mode,
                        source_endpoint,
                        profile_id,
                        cluster_id,
                        security_status,
                        link_quality
    ):
        """
        Callback processing data PDU transmitted by the APS layer.
        """
        asdu.show()
        # Checks if an endpoint matches
        if destination_endpoint not in self.endpoints:
            logger.info("[apl] destination endpoint not found.")
            return

        application = self.endpoints[destination_endpoint]

        # Checks if the profile id matches the one used by the application
        if application.profile_id != profile_id:
            logger.info("[apl] profile identifier doesn't match the application profile.")
            return

        # If we got a match, forward to application data callback
        success = application.on_data(
            asdu,
            source_address,
            source_address_mode,
            cluster_id,
            security_status,
            link_quality
        )
        # If cluster has not been found in the corresponding application, display an error
        if not success:
            logger.info("[apl] cluster not found (cluster_id=0x{:04x}).".format(cluster_id))

    @source('aps', "APSME-JOIN")
    def on_join(
                                self,
                                network_address,
                                extended_address,
                                capability_information,
                                rejoin=False,
                                secure_rejoin=False
    ):
        self.get_service("zdo").on_join(
            network_address,
            extended_address,
            capability_information,
            rejoin=False,
            secure_rejoin=False
        )

    @source('aps', "APSME-TRANSPORT-KEY")
    def on_apsme_transport_key(
                                self,
                                transport_key_data,
                                source_address,
                                standard_key_type
    ):
        """
        Callback processing transport key indicated by the APS layer.
        """
        # Forward to ZDO application
        self.get_service("zdo").on_transport_key(
            source_address,
            standard_key_type,
            transport_key_data
        )
