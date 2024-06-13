from dataclasses import dataclass,fields

@dataclass(repr=False)
class Metadata:
    raw : bool = None
    timestamp : int = None
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
