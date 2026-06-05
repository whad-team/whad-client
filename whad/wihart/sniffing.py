from dataclasses import dataclass, field
from whad.common.sniffing import SniffingEvent
from whad.hub.dot15d4 import LinkOptions, LinkType

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing a Wireless Hart communication.

    :param channel: select the channel to sniff (c)
    :param hide_adv: hide advertisements after first sync (ha)
    :param decrypt: indicate if decryption is enabled (d)
    :param join_key: provide join key (j)
    :param network_key: provide network key (n)
    :param unicast_session_keys: provide unicast session keys - format "ID,KEY[,NONCE]" (u)
    :param broadcast_session_keys: provide broadcast session keys - format "ID,KEY[,NONCE]" (b)

    """
    channel : int = 11
    decrypt : bool = False
    hide_adv: bool = False
    join_key : bytes = field(
        default=bytes.fromhex("7777772e68617274636f6d6d2e6f7267"),
        metadata={"help": ""}
    )
    
    network_key : bytes = field(
        default=None,
    )

    unicast_session_keys : list = field(default_factory=lambda: [])
    broadcast_session_keys : list = field(default_factory=lambda: [])



class TimeSynchronizationEvent(SniffingEvent):
    """Time Synchronization event
    """

    def __init__(self, asn):
        super().__init__("Absolute Slot Number synchronized")
        self.asn = asn

    @property
    def message(self):
        """Readable representation of this event
        """
        return (
            f"asn={self.asn}"
        )


class NewSuperframeEvent(SniffingEvent):
    """New Superframe event
    """

    def __init__(
                    self, 
                    superframe_id,
                    number_of_slots, 
                    flags=0,
                    asn=0

    ):
        super().__init__("New superframe added")
        self.superframe_id=superframe_id
        self.number_of_slots=number_of_slots
        self.flags=flags
        self.asn=asn


    @property
    def message(self):
        """Readable representation of this event
        """
        return (
            f"superframe_id={self.superframe_id}, number_of_slots={self.number_of_slots}"
        )


class NewNetworkKeyEvent(SniffingEvent):
    """New Network Key event
    """
    def __init__(self, network_key):
        super().__init__("New Network Key added")
        self.network_key = network_key

    @property
    def message(self):
        """Readable representation of this event
        """
        return (
            f"network_key={self.network_key.hex()}"
        )


class NewSessionKeyEvent(SniffingEvent):
    """New Session Key event
    """
    def __init__(self, source, destination, session_key, nonce=1, key_type="unicast"):
        super().__init__("New Session Key added")
        self.source = source
        self.destination = destination
        self.nonce = nonce
        self.key_type = key_type
        self.session_key = session_key


    @property
    def message(self):
        """Readable representation of this event
        """
        return (
            f"key_type={self.key_type}, source={hex(self.source)},destination={hex(self.destination)}, session_key={self.session_key.hex()}, nonce={self.nonce}"
        )

class NewLinkEvent(SniffingEvent):
    """New Superframe event
    """

    def __init__(self, 
                        superframe_id,
                        source,
                        time_slot,
                        channel_offset,
                        neighbor,
                        options,
                        link_type
    ):
        super().__init__("New link added")
        self.superframe_id = superframe_id
        self.source = source
        self.time_slot = time_slot
        self.channel_offset = channel_offset
        self.neighbor = neighbor
        self.options = options
        self.link_type = link_type

    @property
    def message(self):
        """Readable representation of this event
        """
        link_options_map = {
           LinkOptions.TRANSMIT : "Tx", 
           LinkOptions.RECEIVE : "Rx", 
           LinkOptions.SHARED : "Sh", 
           LinkOptions.UNKNOWN : "Un"
        }

        link_type_map = {
           LinkType.JOIN : "JOIN", 
           LinkType.DISCOVERY : "DISCOVERY", 
           LinkType.NORMAL : "NORMAL", 
           LinkType.BROADCAST : "BROADCAST"
        }
        
        return (
            f"{'0x{:04x}'.format(self.source)} -> {'0x{:04x}'.format(self.neighbor)}, time_slot={self.time_slot}, channel_offset={self.channel_offset}, type={link_type_map[self.link_type]}, options={link_options_map[self.options]}"
        )