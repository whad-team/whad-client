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

from whad.btmesh.connector import BTMesh

from whad.btmesh.stack import PBAdvBearerLayer
from whad.scapy.layers.btmesh import (
    EIR_PB_ADV_PDU,
    BTMesh_Obfuscated_Network_PDU,
    EIR_BTMesh_Beacon,
)
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.stack.constants import OUTPUT_OOB_AUTH, INPUT_OOB_AUTH
from threading import Event


class UnprovisionedDeviceList:
    """
    Stores the devices for which we have received an Unprovisioned Mesh Beacon in the last 30 seconds
    """

    def __init__(self):
        super().__init__()
        self.__devices = {}
        self.__provisioned_node = []

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
        return (
            dev_uuid in self.__devices
            and (time() - self.__devices[dev_uuid] < 30)
            and dev_uuid not in self.__provisioned_node
        )

    def remove(self, dev_uuid):
        if dev_uuid in self.__devices:
            del self.__devices[dev_uuid]

    def list(self):
        dev_list = []
        for dev_uuid in self.__devices.keys():
            if self.check(dev_uuid):
                dev_list.append(dev_uuid)

        return dev_list

    def add_provisioned_node(self, dev_uuid):
        """
        Add a node to the already provisioned list

        :param dev_uuid: [TODO:description]
        :type dev_uuid: [TODO:type]
        """
        self.__provisioned_node.append(dev_uuid)


class Provisioner(BTMesh):
    def __init__(
        self,
        device,
        prov_stack=PBAdvBearerLayer,
        profile=BaseMeshProfile(),
    ):
        """
        Create a Provisionner device (listening to beacons)
        Can also behave as a "normal" node

        :param device: Device object
        :type device: Device
        :param profile: Profile class used, defaults to BaseMeshProfile
        """
        super().__init__(device, profile, prov_stack=prov_stack, is_provisioner=True)
        self.__unprovisioned_devices = UnprovisionedDeviceList()
        self._is_listening_for_beacons = False

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Sends to stack if provisioning PDU OR
        initiates provisioning if unprovisioned beacon

        :param packet: Packet received
        :type packet: Packet
        """
        if packet.haslayer(EIR_BTMesh_Beacon):
            self.process_beacon(packet.getlayer(EIR_BTMesh_Beacon))
        elif packet.haslayer(EIR_PB_ADV_PDU):
            self._prov_stack.on_provisioning_pdu(packet.getlayer(EIR_PB_ADV_PDU))
        elif self.profile.is_provisioned and packet.haslayer(
            BTMesh_Obfuscated_Network_PDU
        ):
            self._main_stack.on_net_pdu_received(
                packet.getlayer(BTMesh_Obfuscated_Network_PDU), packet.metadata.rssi
            )

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

    def provision_distant_node(self, dev_uuid):
        """
        Provisions the node with the given dev_uuid if it is in the Unprovisioned devices list

        :param dev_uuid: The dev_uuid of the node we want to provision
        :type dev_uuid: UUID
        :returns: True if success, False if fail
        :rtype: bool
        """
        if (
            self.__unprovisioned_devices.check(dev_uuid)
            and self._is_listening_for_beacons
        ):
            self.__unprovisioned_devices.add_provisioned_node(dev_uuid)
            self.__unprovisioned_devices.remove(dev_uuid)
            self._prov_stack.on_new_unprovisoned_device(dev_uuid)

            self.prov_event = Event()

            auth_done = False

            start_time = time()
            duration = 50

            while time() - start_time < duration:
                # Check if event timedout, we fail
                self.prov_event.wait(timeout=5)

                # if distant node is provisioned, finished
                if self.distant_node_provisioned:
                    self.distant_node_provisioned = False
                    return True

                elif not auth_done and self.prov_auth_data is not None:
                    auth_done = True
                    if self.prov_auth_data.auth_method == INPUT_OOB_AUTH:
                        print("AUTH VALUE IS : ")
                        print(self.prov_auth_data.value)

                    # ouput auth should be handled by user code or shell
                    elif self.prov_auth_data.auth_method == OUTPUT_OOB_AUTH:
                        return self.prov_auth_data

            return False

    def resume_provisioning_with_auth(self, value):
        """
        Resume the provisioning process with the user.

        :param value: The value types by the user
        :type value: str
        :returns: True if provisioning success, False if fail
        :rtype: bool
        """

        self.prov_auth_data.value = value
        self._prov_stack.get_layer("pb_adv").on_auth_data(self.prov_auth_data)
        self.prov_event = Event()
        self.prov_event.wait(20)
        if self.distant_node_provisioned:
            self.distant_node_provisioned = False
            return True
        else:
            return False
