"""
Bluetooth Mesh PB-ADV Device connector
=========================================

This connector implements a simple PB-ADV enable device. Both algorithms supported
Can be provisioned by a PB-ADV enabled provisioner
It used the BLE core stack.

It then behaves like a Generic On/Off Server.

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

# Add arguments to connector for models/states

from whad.btmesh.stack import PBAdvBearerLayer
from whad.btmesh.connector.node import BTMeshNode

from whad.btmesh.crypto import (
    NetworkLayerCryptoManager,
    UpperTransportLayerDevKeyCryptoManager,
)
from whad.btmesh.stack.network import NetworkLayer

from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.stack.constants import INPUT_OOB_AUTH, OUTPUT_OOB_AUTH

from scapy.layers.bluetooth4LE import BTLE_ADV_NONCONN_IND, BTLE_ADV, EIR_Hdr
from whad.scapy.layers.btmesh import BTMesh_Unprovisioned_Device_Beacon,EIR_BTMesh_Beacon


from threading import Event, Thread
from time import sleep
from uuid import UUID


class Provisionee(BTMeshNode):
    def __init__(
        self,
        device,
        profile=None,
        net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
        dev_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        unicast_addr=0x0002,
        uuid=UUID("ddddaaaa-aaaa-aa01-0000-000000000000"),
    ):
        """
        Contructor of a Provisionee (node) device
        Support for only one element per node

        :param device: Device object
        :type device: Device
        :param profile: Profile class used for the node (elements and models layout), defaults to None
        :param net_key: If auto provisioned : primary NetKey , defaults to bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
        :type net_key: Bytes, optional
        :param dev_app_key: If auto provisioned : primary app key and dev key (both the same value), defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type dev_app_key: Bytes, optional
        :param unicast_addr: If auto provisioned, unicast addr, defaults to 0x0002
        :type unicast_addr: int, optional
        :param uuid: The UUID of the node, defaults to UUID("7462d668-bc88-3473-0000-000000000012")
        :type: UUID, optional
        """
        super().__init__(
            device,
            profile,
        )

        # Used to stop the unprov_beacons_sending_thread function from running
        self._unprov_beacons_sending = False

        # UUID of the node, used in beacons
        self.uuid = uuid

    def set_uuid(self, uuid):
        """
        Sets the UUID of the device for provisioning process
        IN THEORY SHOULD BE LINKED TO ADVA ADDRESS USED IN ADV PACKETS !

        :param uuid: UUID to use (16 bytes long hex string)
        :type uuid: str
        :returns: True if success, False if fail
        :rtype: bool
        """
        try:
            self.uuid = UUID(uuid)
        except Exception:
            return False

        return True

    def start_provisioning(self):
        """
        Starts the provisioning process (sending beacons, accepting invite ..) andf starts the connector for lisiting packets
        """
        self.start()
        self.start_unprovisioned_beacons_sending()

        self.prov_event = Event()

        auth_done = False
        self.prov_event.wait(timeout=60)

        # if we have prov_data, provisioning finished
        if self._prov_data is not None:
            self.provisioning_finished()
            return True

        elif not auth_done and self.prov_auth_data is not None:
            auth_done = True
            if self.prov_auth_data.auth_method == OUTPUT_OOB_AUTH:
                print("AUTH VALUE IS : ")
                print(self.prov_auth_data.value)
                res = self.resume_provisioning_with_auth()
                return res

            # Input auth should be handled by user code or shell
            elif self.prov_auth_data.auth_method == INPUT_OOB_AUTH:
                return self.prov_auth_data

        return False

    def provisioning_finished(self):
        """
        Called when the local node has been successfully provisioned to instanciate stack and keys
        """
        primary_net_key = NetworkLayerCryptoManager(
            key_index=self._prov_data.key_index, net_key=self._prov_data.net_key
        )
        dev_key = UpperTransportLayerDevKeyCryptoManager(
            provisioning_crypto_manager=self._prov_data.provisioning_crypto_manager
        )
        self.profile.provision(
            primary_net_key,
            dev_key,
            self._prov_data.iv_index,
            self._prov_data.flags,
            self._prov_data.unicast_addr,
        )

        self.profile.is_provisioned = True

    def resume_provisioning_with_auth(self, value=None):
        """
        Resume the provisioning process with the user.

        :param value: The value typed by the user if INPUT_OOB_AUTH, default
        :type value: str, optional
        """
        # If output oob, give value to stack
        if self.prov_auth_data.auth_method == INPUT_OOB_AUTH and value is not None:
            self.prov_auth_data.value = value
            self._prov_stack.on_provisioning_auth_data(self.prov_auth_data)

        self.prov_event = Event()
        self.prov_event.wait(20)
        if self._prov_data is not None:
            self.provisioning_finished()
            return True
        return False

    def start_unprovisioned_beacons_sending(self):
        """
        Starts the sending of an Unprovisioned Device Beacons (provisioning)
        """

        self._unprov_beacons_sending = True
        thread = Thread(target=self._unprov_beacons_sending_thread)
        thread.start()

    def stop_unprovisioned_beacons(self):
        """
        Stops the sending of BTMesh_Unprovisioned_Device_Beacon
        """
        self._unprov_beacons_sending = False

    def _unprov_beacons_sending_thread(self):
        """
        Thread that runs when sending unprovisioned device beacons
        """
        beacon_data = BTMesh_Unprovisioned_Device_Beacon(
            device_uuid=self.uuid, uri_hash=0
        )

        pkt_beacon = EIR_Hdr(type=0x2B) / EIR_BTMesh_Beacon(
            mesh_beacon_type=0x00, unprovisioned_device_beacon_data=beacon_data
        )
        for i in range(20):
            if not self._unprov_beacons_sending:
                return
            self.send_raw(pkt_beacon)
            sleep(2)
