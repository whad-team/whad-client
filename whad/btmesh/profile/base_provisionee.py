"""
Bluetooth Mesh Base Profile for a provisionee

Supports only the Configuration Server Model on the primary element
"""

from whad.btmesh.profile import BaseMeshProfile


class BaseMeshProfileProvisionee(BaseMeshProfile):
    """
    Base class for Blutooth Mesh Profiles as a provisionee node.
    """

    def __init__(
        self,
        auto_prov_net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
        auto_prov_dev_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        auto_prov_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        auto_prov_unicast_addr=b"\x00\x02",
    ):
        """
        Init of the BTMesh generic profile for a provisionee node.

        :param auto_prov_net_key: Primary net key of the node (index 0) if auto_provisioned, defaults to bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
        :type auto_prov_net_key: bytes, optional
        :param auto_prov_dev_key: Dev key of the node if auto_provisioned , defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type auto_prov_dev_key: bytes, optional
        :param auto_prov_app_key: App key of the node (index 0, binded to net_key at index 0) if auto_provisioned, defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type auto_prov_app_key: bytes, optional
        :param auto_prov_unicast_addr: Primary unicast_addr if auto_provisioned, defaults to b"\x00\x02"
        :type auto_prov_unicast_addr: bytes, optional
        """

        # Elements of the node. Ordered.
        super().__init__(
            auto_prov_net_key=auto_prov_net_key,
            auto_prov_dev_key=auto_prov_dev_key,
            auto_prov_app_key=auto_prov_app_key,
            auto_prov_unicast_addr=auto_prov_unicast_addr,
        )

    def _populate_elements_and_models(self):
        """
        Populate elements and models for the node (except the ConfigurationModelServer, HealthModelServer and primary element creation, created by default)
        """
        super()._populate_base_models()
        pass
