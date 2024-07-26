from typing import Union
from dataclasses import dataclass, field, fields


def channel_to_frequency(channel):
    '''
    Converts 802.15.4 channel to frequency (in Hz).
    '''
    return 1000000 * (2405 + 5 * (channel - 11))

@dataclass(repr=False)
class Metadata:
    raw : bool = None
    decrypted : bool = None
    timestamp : Union[int, float] = None
    channel : int = None
    rssi : int = None

    def convert_to_header(self):
        pass

    def __repr__(self):
        metadatas = []
        for field in fields(self.__class__):
            if hasattr(self, field.name) and getattr(self,field.name) is not None:
                metadatas.append("{}={}".format(field.name, getattr(self,field.name)))

        if len(metadatas) == 0:
            return ""
        else:
            return "[ " + ", ".join(metadatas) + " ]"
