from enum import IntEnum

class ClickType(IntEnum):
    NONE = 0
    LEFT = 1
    RIGHT = 2
    LEFT_RIGHT = 3
    MIDDLE = 4
    LEFT_MIDDLE = 5
    RIGHT_MIDDLE = 6

    def __str__(self):
        if self == ClickType.NONE:
            return ""
        elif self == ClickType.LEFT:
            return "L"
        elif self == ClickType.RIGHT:
            return "R"
        elif self == ClickType.LEFT_RIGHT:
            return "LR"
        elif self == ClickType.MIDDLE:
            return "M"
        elif self == ClickType.LEFT_MIDDLE:
            return "LM"
        elif self == ClickType.RIGHT_MIDDLE:
            return "RM"

class UnifyingRole(IntEnum):
    DONGLE = 0
    MOUSE = 1
    KEYBOARD = 2


class MultimediaKey(IntEnum):
    VOLUME_DOWN = 0xEA
    VOLUME_UP = 0xE9
    VOLUME_TOGGLE = 0xE2
