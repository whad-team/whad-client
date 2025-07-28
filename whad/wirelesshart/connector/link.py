class Link:
    def __init__(self, src, join_slot, offset, neighbor=0xffff, options=0x4, type=0x1):
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
        return f"Link(src={self.src}, slot={self.join_slot}, offset={self.offset})"