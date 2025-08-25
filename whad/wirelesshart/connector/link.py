class Link:
    TYPE_NORMAL = 0x0
    TYPE_DISCOVERY = 0x1
    TYPE_BROADCAST = 0x2
    TYPE_JOIN = 0x3
    OPTIONS_SHARED = 0x1
    OPTIONS_RECEIVE = 0x2
    OPTIONS_TRANSMIT = 0x4
    BROADCAST = 0xffff
    def __init__(self, src, join_slot, offset, neighbor=BROADCAST, options=OPTIONS_TRANSMIT, type=TYPE_DISCOVERY):
        self.src = src
        self.join_slot = join_slot
        self.offset = offset
        self.neighbor = neighbor
        self.options = options
        self.type = type
        
    def __eq__(self, other):
        return (
            isinstance(other, Link)
            and self.join_slot == other.join_slot
            and self.offset == other.offset
        )
        
    def equals_modulo(self, other, diviser:int):
        return(
            isinstance(other, Link)
            and self.offset == other.offset
            and self.join_slot % diviser == other.join_slot % diviser
        )
         

    def __hash__(self):
        return hash((self.join_slot))
        
    def getBytesArray(self):
        return bytearray([
            self.src // 256,
            self.src % 256,
            self.join_slot // 256,
            self.join_slot % 256,
            self.offset,
            self.neighbor// 256,
            self.neighbor % 256,
            self.options,
            self.type
        ])
        
    def __repr__(self):
        return f"Link(src={self.src}, neighbor={self.neighbor}, slot={self.join_slot},type={self.type}, offset={self.offset}, options={self.options})"