"""BLE packet replay connector.

This connector can be used either in standalone to replay packets or combined
with whadreplay.
"""
from dataclasses import dataclass
from scapy.packet import Packet
from whad.device import WhadDevice
from whad.exceptions import UnsupportedCapability
from whad.ble.connector import Central
from whad.ble.exceptions import PeripheralNotFound
from whad.scapy.layers import NordicBLE
from scapy.layers.bluetooth4LE import BTLE_DATA, BTLE_RF, BTLE_CTRL, LL_CONNECTION_PARAM_REQ, LL_FEATURE_REQ, \
    LL_VERSION_IND, LL_PING_REQ, LL_PING_RSP, LL_CONNECTION_PARAM_RSP, LL_FEATURE_RSP
from scapy.layers.bluetooth import L2CAP_Connection_Parameter_Update_Request, L2CAP_Connection_Parameter_Update_Response
from whad.common.replay import ReplayRole, ReplayInterface

@dataclass
class ReplayConfiguration:
    """
    Configuration for the Bluetooth Low Energy replay tool.

    :param target: specify the target BD address (t)
    :param random: target is using a random address (r)
    """
    target : str = None
    random : bool = True


class Replay(Central, ReplayInterface):
    """Replay BLE PDUs using a central device.

    We need to be smart here and detect any procedure initiated by a Peripheral
    to avoid sending back responses that would mess with the actual connection
    in which packets are replayed.

    This includes:

    - MTU exchange requests (ATT)
    - Feature exchange (LL_SLAVE_FEATURE_REQ, LL_FEATURE_REQ)
    - Version exchange
    - Connection parameters request procedure
    - Ping procedure
    - L2CAP Connection Update Parameter procedure
    """

    def __init__(self, device : WhadDevice, pcapfile:str, role : int):
        Central.__init__(self, device)
        ReplayInterface.__init__(self, role)
        self.__target = None
        self.__active_procedures = []

        # Make sure our device supports central mode
        if not self.can_be_central():
            raise UnsupportedCapability("Central")

    def prepare(self, config) -> bool:
        """Prepare this replay interface.
        """
        # Connect to our target device
        try:
            self.start()
            self.__target = self.connect(config.target, config.random)
            
            # Success !
            return True
        except PeripheralNotFound as err:
            # We were not able to initialize our replay instance
            return False

    def analyze_incoming_pdu(self, packet : BTLE_DATA):
        """Analyze incoming PDU to detect any procedure initiated by the remote
        Peripheral.

        Maintain the active procedures accordingly in order to avoid 
        """
        # Does the peripheral initiates a version exchange ?
        if packet.haslayer(LL_VERSION_IND) and 'version' not in self.__active_procedures:
            self.__active_procedures.append('version')
        # Or a ping ?
        elif packet.haslayer(LL_PING_REQ):
            self.__active_procedures.append('ping')
        # Or a connection parameter update procedure ?
        elif packet.haslayer(LL_CONNECTION_PARAM_REQ):
            self.__active_procedures.append('connparams')
        # Or a feature exchange procedure ?
        elif packet.haslayer(LL_FEATURE_REQ):
            self.__active_procedures.append('features')
        # Or a L2CAP connection parameter update procedure ?
        elif packet.haslayer(L2CAP_Connection_Parameter_Update_Request):
            self.__active_procedures.append('llconnparams')
        

    def should_send_pdu(self, packet: BTLE_DATA):
        """Determine if we should send a specific PDU
        """
        # Is this PDU an answer to a version exchange procedure initiated by the remote device ?
        if packet.haslayer(LL_VERSION_IND) and 'version' in self.__active_procedures:
            # Procedure is complete
            self.__active_procedures.remove('version')
            # But we shall not send this PDU
            return False
        elif packet.haslayer(LL_PING_RSP) and 'ping' in self.__active_procedures:
            # Procedure is complete
            self.__active_procedures.remove('ping')
            return False
        elif packet.haslayer(LL_CONNECTION_PARAM_RSP) and 'connparams' in self.__active_procedures:
            # Procedure is complete
            self.__active_procedures.remove('connparams')
            return False
        elif packet.haslayer(LL_FEATURE_RSP):
            # Procedure is complete
            self.__active_procedures.remove('features')
            return False
        elif packet.haslayer(L2CAP_Connection_Parameter_Update_Response) and 'llconnparams' in self.__active_procedures:
            # Procedure is complete
            self.__active_procedures.remove('llconnparams')
            return False
        else:
            # Check if interface supports sending control PDUs (required to send control PDUs)
            if packet.haslayer(BTLE_CTRL):
                return self.can_inject()
            else:
                return True

    def send_packet(self, packet : Packet):
        """Send packet callback.

        Based on the current replay role, packet must be sent or not.
        """
        # First, we make sure this packet has a valid TAP
        if packet.haslayer(NordicBLE):
            nordic_layer = packet[NordicBLE]
            if nordic_layer.haslayer(BTLE_DATA):
                pdu = nordic_layer[BTLE_DATA]

                # Only allow replay of packets sent by master (central device)
                if (nordic_layer.flags & 2) and self.is_emitter():
                    if self.should_send_pdu(pdu):
                        self.send_data_pdu(pdu, conn_handle=self.__target.conn_handle)

                        # Packet sent, return True
                        return True
                    else:
                        # Packet not sent
                        return False
                else:
                    self.analyze_incoming_pdu(pdu)
        
        elif packet.haslayer(BTLE_RF):
            btle_rf = packet[BTLE_RF]
            if btle_rf.haslayer(BTLE_DATA):
                pdu = btle_rf[BTLE_DATA]

                # Only allow replay of packets sent by master (central device)
                if btle_rf.type == 0x2 and self.is_emitter():
                    if self.should_send_pdu(pdu):
                        self.send_data_pdu(pdu, conn_handle=self.__target.conn_handle)
                        return True
                    else:
                        return False
                else:
                    self.analyze_incoming_pdu(pdu)
                
        # Packet cannot be sent, return False
        return False
        