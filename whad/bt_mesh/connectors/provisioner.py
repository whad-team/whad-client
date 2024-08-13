"""
Bluetooth Mesh PB-ADV Provisioner connector
=========================================

This connector implements a simple PB-ADV stack. Both algorithms supported
Can provide a device sending unprovisioned beacons and supporting PB-ADV provisioning
It used the BLE core stack

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

from random import randbytes
from time import time

from whad.bt_mesh.connectors import BTMesh
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_NONCONN_IND, EIR_Hdr
from whad.scapy.layers.bt_mesh import EIR_BTMesh_Beacon
from whad.ble import UnsupportedCapability, message_filter, BleDirection

from whad.bt_mesh.stack import PBAdvBearerLayer
from scapy.all import raw
from whad.scapy.layers.bt_mesh import EIR_PB_ADV_PDU
import pdb


class UnprovisionedDeviceList:
    """
    Stores the devices for which wa have received an Unprovisioned Mesh Beacon in the last 30 seconds
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
    def __init__(self, device, connection=None):
        """Create a Provisioner Device"""
        super().__init__(
            device, stack=PBAdvBearerLayer, options={"role": "provisioner"}
        )
        self.__unprovisioned_devices = UnprovisionedDeviceList()

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
                print("UNPROVISIONED BEACON RECEIVED FOR > " + str(beacon_data.device_uuid))
                choice = input("PROVISION DEVICE ? Y/N :")
                if choice == "Y":
                    self.__unprovisioned_devices.add_provisioned_node(
                        beacon_data.device_uuid
                    )
                    self._stack.on_new_unprovisoned_device(beacon_data.device_uuid)
