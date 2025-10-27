from scapy.layers.bluetooth4LE import (
    BTLE_ADV,
    EIR_Hdr,
    BTLE_ADV_NONCONN_IND
)
from whad.exceptions import (
        UnsupportedCapability,
        RequiredImplementation,
        WhadDeviceDisconnected
)
from whad.btmesh.connector.bearer import Bearer
from whad.ble.connector import BLE

class AdvBearer(Bearer):
    """
    Implements a basic ADV bearer for Bluetooth mesh.
    """

    def __init__(self, connector):
        super().__init__(connector)
        # Attribute indicating the state of the bearer
        self.__started = False

        # Configuration of the advertising bearer
        self.configuration = {
            # BD address in use by the bearer, default is random
            "bd_address" : "AA:BB:CC:DD:EE:FF", 
            # Channel in use, if None use three primary advertising channels
            "channel" : None,
            # Default scanning interval
            "interval" : 50,
            # Minimal number of repeatition for an outgoing packet transmission
            "repeat" : 2
        }


    def configure(self, **kwargs):
        """
        Updates the configuration in use by the ADV Bearer according to the provided named parameters.
        """

        super().configure(**kwargs)
        if "bd_address" in kwargs:
            self.connector.set_bd_address(kwargs["bd_address"], public=False)

    def send(self, packet):
        """
        Sends the packet through the BLE advertising bearer

        :param packet: Packet to send
        :type packet: Packet (`EIR_Element` subclass)
        """

        # If channel is None, transmit on every channel 37,38 & 39
        channel = self.configuration["channel"]
        if channel is None:
            channel = 0

        # Forge an ADV_NONCONN_IND PDU with configured BD address
        adv_pdu = BTLE_ADV_NONCONN_IND(
                AdvA=self.configuration["bd_address"],
                data=packet
        )

        # Repeated transmission
        for _ in range(self.configuration["repeat"]):
            # Calls the underlying BLE `send_adv_pdu` method 
            res = self.connector.send_adv_pdu(
                    adv_pdu,
                    channel = channel
            )
        
        return res


    def start(self):
        """
        Start the ADV bearer. 
        """

        if self.configuration["channel"] is None:
            if not self.connector.can_scan():
                raise UnsupportedCapability("Scan")

            success = self.connector.enable_scan_mode(
                interval=self.configuration["interval"]
            )
        elif self.configuration["channel"] in (37,38,39):
            success = self.connector.sniff_advertisements(
                channel=self.configuration["channel"]
            )
        else:
            raise UnsupportedCapability("SniffingAdvertisements")

        if not success:
            return False

        if self.connector._start():
            self.__started = True

            return True
        return False

    def stop(self):
        """
        Stop the ADV bearer.
        """
        if self.__started:
            self.connector._stop()
            self.__started = False

    def on_adv_pdu(self, packet):
        """
        Callback called when an incoming advertising packet is received, 
        filters BT Mesh packets according to the ADV bearer.
        """  
        if self.bt_mesh_filter(packet):
            self.connector.process_rx_packets(packet)

    def bt_mesh_filter(self, packet, ignore_regular_adv=True) -> bool:
        """
        Filter out non Mesh advertising packets

        :param packet: incoming packet
        :type packet: bytes
        :param ignore_regular_adv: boolean indicating if regular advertisements must be ignored
        :type ignore_regular_adv: bool
        :return: `True` if incoming packet is a valid BT Mesh packet, `False` otherwise.
        :rtype: bool
        """
        if BTLE_ADV in packet:
            if hasattr(packet, "data"):
                if EIR_Hdr in packet and (
                    any(
                        [
                            isinstance(i, EIR_Hdr) and i.type in (0x29, 0x2A, 0x2B)
                            for i in packet.data
                        ]
                    )
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

        return False