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

from whad.ble.connector import Sniffer
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_NONCONN_IND, EIR_Hdr
from whad.scapy.layers.bt_mesh import EIR_BTMesh_Beacon
from whad.ble import UnsupportedCapability, message_filter, BleDirection
from whad.hub.ble import Injected, Synchronized
from whad.ble.sniffing import SynchronizedConnection

from whad.ble.exceptions import ConnectionLostException


from whad.bt_mesh.stack import PBAdvBearerLayer
from whad.scapy.layers.bt_mesh import BTMesh_Provisioning_Hdr


class UnprovisionedDeviceList:
    """
    Stores the devices for which wa have received an Unprovisioned Mesh Beacon in the last 30 seconds
    """

    def __init__(self):
        super().__init__()
        self._devices = {}

    def update(self, dev_uuid):
        """
        Add or update a dev_uuid for which we received an Unprovisioned Beacon

        :param dev_uuid: [TODO:description]
        :type dev_uuid: [TODO:type]
        """
        self._devices[dev_uuid] = time()

    def check(self, dev_uuid):
        """
        Returns True if devices has sent an Unprovisioned Mesh beacon in the last 30 sec

        :param dev_uuid: [TODO:description]
        :type dev_uuid: [TODO:type]
        """
        return dev_uuid in self._devices and (time() - self._devices[dev_uuid] < 30)

    def remove(self, dev_uuid):
        if dev_uuid in self._devices:
            del self._devices[dev_uuid]

    def list(self):
        dev_list = []
        for dev_uuid in self._devices.keys():
            if self.check(dev_uuid):
                dev_list.append(dev_uuid)

        return dev_list


class Provisioner(Sniffer):
    def __init__(self, device, connection=None):
        """Create a Provisioner Device"""
        super().__init__(device)
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

        self.__stack = PBAdvBearerLayer(connector=self, options={"role": "provisioner"})
        self.__stack.configure({"role": "provisioner"})
        self.attach_callback(
            callback=lambda pkt: self.on_recv_adv(pkt),
            filter=lambda pkt: self.bt_mesh_filter(pkt, True),
            on_transmission=False,
        )

        # List of unprovisioned devices waiting to be provisioned
        self.__unprovisioned_devices = UnprovisionedDeviceList()

    def bt_mesh_filter(self, packet, ignore_regular_adv):
        """
        Filter out non Mesh advertising packets
        """
        if BTLE_ADV in packet:
            if hasattr(packet, "data"):
                if EIR_Hdr in packet and (
                    any([i.type in (0x29, 0x2A, 0x2B) for i in packet.data])
                    or any(
                        h in [[0x1827], [0x1828]]
                        for h in [
                            i.svc_uuids
                            for i in packet.data
                            if hasattr(i, "svc_uuids") and not ignore_regular_adv
                        ]
                    )
                ):
                    return True

    def on_recv_adv(self, packet: BTLE):
        """
        Process an received advertising Mesh packet. Send it to our PB-ADV layer
        """
        if packet.haslayer(EIR_BTMesh_Beacon):
            self.process_beacon(packet.getlayer(EIR_BTMesh_Beacon))

    def process_beacon(self, packet):
        """
        Process a received beacon (only Unprovisioned Beacons accepted for now)

        :param packet:
        :type packet: EIR_BTMesh_Beacon
        """
        if packet.mesh_beacon_type == 0x00:
            beacon_data = packet.unprovisioned_device_beacon_data
            self.__unprovisioned_devices.update(beacon_data.device_uuid)
            print("UNPROVISIONED BEACON RECEIVED FOR > " + str(beacon_data.device_uuid))
            choice = input("PROVISION DEVICE ? Y/N :")
            if choice == "Y":
                self.__stack.on_new_unprovisoned_device(beacon_data.device_uuid)

    def send_raw(self, packet, channel=37):
        """
        Sends the packet through the BLE advertising bearer

        :param packet: Packet to send
        :type packet: EIR_PB_ADV_PDU
        :param channel: [TODO:description], defaults to 37
        :type channel: [TODO:type], optional
        """

        AdvA = randbytes(6).hex(":")  # random in spec
        adv_pkt = BTLE_ADV(TxAdd=1) / BTLE_ADV_NONCONN_IND(AdvA=AdvA, data=packet)

        return self.send_pdu(
            adv_pkt,
            access_address=0x8E89BED6,
            conn_handle=channel,
            direction=BleDirection.UNKNOWN,
        )
