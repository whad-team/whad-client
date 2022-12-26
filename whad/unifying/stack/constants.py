from enum import IntEnum

class ClickType(IntEnum):
    NONE = 0
    LEFT = 1
    RIGHT = 2
    MIDDLE = 3


class UnifyingRole(IntEnum):
    DONGLE = 0
    MOUSE = 1
    KEYBOARD = 2
