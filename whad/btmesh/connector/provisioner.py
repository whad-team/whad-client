"""
Bluetooth Mesh PB-ADV Provisioner connector
=========================================

This connector implements a simple PB-ADV stack. Both algorithms supported
Can provide a device sending unprovisioned beacons and supporting PB-ADV provisioning
It used the BLE core stack

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

from time import time

from whad.btmesh.connector.node import BTMeshNode

from whad.btmesh.stack import PBAdvBearerLayer
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.stack.constants import OUTPUT_OOB_AUTH, INPUT_OOB_AUTH
from whad.btmesh.crypto import UpperTransportLayerDevKeyCryptoManager
from whad.btmesh.stack.utils import Node
from threading import Event


class UnprovisionedDeviceList:
    """
    Stores the devices for which we have received an Unprovisioned Mesh Beacon in the last 30 seconds
    """

    def __init__(self):
        super().__init__()
        self.__devices = {}

    def update(self, dev_uuid):
        """
        Add or update a dev_uuid for which we received an Unprovisioned Beacon

        :param dev_uuid: [TODO:description]
        :type dev_uuid: [TODO:type]
        """
        self.__devices[dev_uuid] = time()

    def check(self, dev_uuid):
        """
        Returns True if devices has sent an Unprovisioned Mesh beacon in the last 30 sec
        and not already provisioned/in provisioning process

        :param dev_uuid: [TODO:description]
        :type dev_uuid: [TODO:type]
        """
        return dev_uuid in self.__devices and (time() - self.__devices[dev_uuid] < 30)

    def remove(self, dev_uuid):
        if dev_uuid in self.__devices:
            del self.__devices[dev_uuid]

    def list(self):
        dev_list = []
        for dev_uuid in self.__devices.keys():
            if self.check(dev_uuid):
                dev_list.append(dev_uuid)

        return dev_list


class Provisioner(BTMeshNode):
    def __init__(
        self,
        device,
        profile=None,
    ):
        """
        Create a Provisionner device (listening to beacons)
        Can also behave as a "normal" node

        :param device: Device object
        :type device: Device
        :param profile: Profile to use, defaults to BaseMeshProfile
        :type profile: BaseMeshProfile
        """
        super().__init__(device, profile)

        self.profile.is_provisioner = True

        self.__unprovisioned_devices = UnprovisionedDeviceList()
        self._is_listening_for_beacons = False
        self._is_currently_provisioning = False

        self._prov_stack = PBAdvBearerLayer(connector=self, options={})

    def stop_listening_beacons(self):
        """
        Stops the listening for beacons
        """
        self._is_listening_for_beacons = False

    def start_listening_beacons(self):
        """
        Starts the listening for beacons
        """
        self._is_listening_for_beacons = True

    def process_beacon(self, packet):
        """
        Process a received beacon (only Unprovisioned Beacons accepted for now)

        :param packet:
        :type packet: EIR_BTMesh_Beacon
        """
        if packet.mesh_beacon_type == 0x00:
            beacon_data = packet.unprovisioned_device_beacon_data
            if self._is_listening_for_beacons:
                self.__unprovisioned_devices.update(beacon_data.device_uuid)

    def get_unprovisioned_devices(self):
        """
        Returns the lastly received Unprovisioned Device Beacons info we received
        """
        return self.__unprovisioned_devices.list()

    def get_prov_data(self, prov_data):
        """
        Fills the ProvisioningData of the distant node with relevant information

        :param prov_data: The object to fill
        """
        net_key = self.profile.get_net_key(0)
        prov_data.net_key = net_key.net_key
        prov_data.key_index = net_key.key_index
        prov_data.flags = b"\x00"
        prov_data.iv_index = self.profile.iv_index

        # Get an available unicast addr that fits the addr range
        # For now we take the lastly provisioned node addr + range + 1 (no deletion of nodes)
        last_node = sorted(self.profile.get_all_nodes().items())[-1][1]
        prov_data.unicast_addr = last_node.address + last_node.addr_range

    def provision_distant_node(self, dev_uuid):
        """
        Provisions the node with the given dev_uuid if it is in the Unprovisioned devices list

        :param dev_uuid: The dev_uuid of the node we want to provision
        :type dev_uuid: UUID
        :returns: True if success, False if fail
        :rtype: bool
        """
        if self.__unprovisioned_devices.check(dev_uuid):
            self._is_currently_provisioning = True
            self.__unprovisioned_devices.remove(dev_uuid)
            self._prov_stack.on_new_unprovisoned_device(dev_uuid)

            self.prov_event = Event()

            auth_done = False

            duration = 60
            self.prov_event.wait(timeout=60)

            # if distant node is provisioned, finished
            if self._prov_data is not None:
                self.add_distant_after_provisioning()
                return True

            elif not auth_done and self.prov_auth_data is not None:
                auth_done = True
                if self.prov_auth_data.auth_method == INPUT_OOB_AUTH:
                    print("AUTH VALUE IS : ")
                    print(self.prov_auth_data.value)
                    res = self.resume_provisioning_with_auth()
                    return res

                # ouput auth should be handled by user code or shell
                elif self.prov_auth_data.auth_method == OUTPUT_OOB_AUTH:
                    return self.prov_auth_data

            # provisioning failed
            return False

    def resume_provisioning_with_auth(self, value=None):
        """
        Resume the provisioning process after auth value has been
        displayed/entered

        :param value: The value types by the user if INPUT_OOB_AUTH, defaults to None
        :type value: str, optional
        :returns: True if provisioning success, False if fail
        :rtype: bool
        """

        # If output oob, give value to stack
        if self.prov_auth_data.auth_method == OUTPUT_OOB_AUTH and value is not None:
            self.prov_auth_data.value = value
            self._prov_stack.get_layer("pb_adv").on_provisioning_auth_data(
                self.prov_auth_data
            )
        self.prov_event = Event()
        self.prov_event.wait(20)
        self._is_currently_provisioning = False
        if self._prov_data is not None:
            self.add_distant_after_provisioning()
            return True
        else:
            return False

    def add_distant_after_provisioning(self):
        """
        After provisioning of a distant node is successfull, add it to our database
        """
        new_node = Node(
            address=self._prov_data.unicast_addr,
            addr_range=self._prov_data.addr_range,
            dev_key=UpperTransportLayerDevKeyCryptoManager(
                provisioning_crypto_manager=self._prov_data.provisioning_crypto_manager
            ),
        )
        self.profile.add_distant_node(new_node)
        self._prov_data = None
