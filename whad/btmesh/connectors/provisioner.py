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

from whad.btmesh.connectors import BTMesh

from whad.btmesh.stack import PBAdvBearerLayer
from whad.scapy.layers.btmesh import (
    EIR_PB_ADV_PDU,
    BTMesh_Obfuscated_Network_PDU,
    EIR_BTMesh_Beacon,
)
from whad.btmesh.profile import BaseMeshProfile


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
        profile=BaseMeshProfile(),
        auto_provision=False,
        net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
        app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        unicast_addr=b"\x00\x01",
    ):
        """
        Create a Provisionner device (listening to beacons)
        Can also behave as a "normal" node

        :param device: Device object
        :type device: Device
        :param profile: Profile class used, defaults to BaseMeshProfile
        :param auto_provision: Choose if auto provisioning needed to be node, defaults to False
        :type auto_provision: Bool, optional
        :param net_key: If auto provisioned : primary NetKey , defaults to bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
        :type net_key: Bytes, optional
        :param app_key: If auto provisioned : primary app key and dev key, defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type app_key: Bytes, optional
        :param unicast_addr: If auto provisioned, unicast addr, defaults to b"\x00\x01"
        :type unicast_addr: Bytes, optional
        """
        super().__init__(
            device, profile, stack=PBAdvBearerLayer, options={"role": "provisioner"}
        )
        self.__unprovisioned_devices = UnprovisionedDeviceList()

        if auto_provision:
            self.auto_provision(net_key, app_key, unicast_addr)

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
            self._stack.on_provisioning_pdu(packet.getlayer(EIR_PB_ADV_PDU))
        elif self.is_provisioned and packet.haslayer(BTMesh_Obfuscated_Network_PDU):
            self._main_stack.on_net_pdu_received(
                packet.getlayer(BTMesh_Obfuscated_Network_PDU), packet.metadata.rssi
            )

    def process_beacon(self, packet):
        """
        Process a received beacon (only Unprovisioned Beacons accepted for now)

        :param packet:
        :type packet: EIR_BTMesh_Beacon
        """
        if packet.mesh_beacon_type == 0x00:
            beacon_data = packet.unprovisioned_device_beacon_data
            self.__unprovisioned_devices.update(beacon_data.device_uuid)
            if self.__unprovisioned_devices.check(beacon_data.device_uuid):
                print(
                    "UNPROVISIONED BEACON RECEIVED FOR > "
                    + str(beacon_data.device_uuid)
                )
                choice = input("PROVISION DEVICE ? Y/N :")
                if choice == "Y":
                    self.__unprovisioned_devices.add_provisioned_node(
                        beacon_data.device_uuid
                    )
                    self._stack.on_new_unprovisoned_device(beacon_data.device_uuid)
