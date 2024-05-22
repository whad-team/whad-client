from dataclasses import dataclass, field
from whad.common.sniffing import SniffingEvent

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing a RF4CE communication.

    :param channel: select the channel to sniff (c)
    :param decrypt: indicate if decryption is enabled (d)
    :param keys: provide decryption keys (k)
    :param audio: decode audio stream (audio)
    :param pairing: sniff pairing procedure and break key if possible(p)
    :param addresses: provide node extended addresses (a)

    """
    channel : int = 15
    decrypt : bool = False
    pairing : bool = False
    audio : bool = False
    audio_file : str = ""
    keys : list = field(default_factory=lambda: [])
    addresses : list = field(default_factory=lambda: [])


class KeyExtractedEvent(SniffingEvent):
    """Event indicating that a key has been extracted from pairing
    """
    def __init__(self, key):
        super().__init__("Key extracted")
        self.key = key

    @property
    def message(self):
        return "key={}".format(self.key.hex())
