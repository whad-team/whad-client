"""
Bluetooth Mesh PB-ADV Provisioner connector
=========================================

This connector implements a simple PB-ADV stack. Both algorithms supported
Can provide a device sending unprovisioned beacons and supporting PB-ADV provisioning
It used the BLE core stack

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

from whad.ble.connector.sniffer import Injector
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, EIR_Hdr
from whad.ble import UnsupportedCapability, message_filter, BleDirection

from whad.bt_mesh.stack import PBAdvBearerLayer


class Provisioner(Injector):
    def __init__(self, device, connection=None):
        """Create a Provisioner Device"""
        super().__init__(device)
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

        self._stack = PBAdvBearerLayer()
        self._stack.configure({"role": "provisioner"})
        self.attach_callback(
            callback=lambda pkt: self.on_recv_adv(pkt),
            filter=lambda pkt: self.bt_mesh_filter(pkt, True),
        )


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

    def on_recv_adv(self, packet):
        """
        Process an received advertising Mesh packet
        """
        packet.show()



    def raw_inject(self, packet, channel=37):
        if BTLE in packet:
            access_address = packet.access_addr
        elif BTLE_ADV in packet:
            access_address = 0x8E89BED6
        elif BTLE_DATA in packet:
            if self.__connection is not None:
                access_address = self.__connection.access_address
            else:
                access_address = 0x11223344  # default value

        return self.send_pdu(
            packet,
            access_address=access_address,
            conn_handle=channel,
            direction=BleDirection.UNKNOWN,
        )

    def start_provisioner(self):
        # start sniffer
        self.start()
