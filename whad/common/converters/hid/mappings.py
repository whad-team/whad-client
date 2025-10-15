"""Human Interface Device (HID) mappings for HID converter.
"""
from .maps import HID_MAP

# Special keys
HID_SPECIALS = {
    (0, 0): "",
    (0, 4): "LALT",
    (0, 2): "SHIFT",
    (0, 1): "CTRL",
    (0, 64): "RALT",
    (0, 32): "SHIFT",
    (0, 16): "CTRL",
    (0, 8): "GUI",
    (71, 0): "SCROLLLOCK",
    (40, 0): "ENTER",
    (69, 0): "F12",
    (74, 0): "HOME",
    (67, 0): "F10",
    (66, 0): "F9",
    (41, 0): "ESCAPE",
    (75, 0): "PAGEUP",
    (43, 0): "TAB",
    (70, 0): "PRINTSCREEN",
    (59, 0): "F2",
    (57, 0): "CAPSLOCK",
    (58, 0): "F1",
    (61, 0): "F4",
    (63, 0): "F6",
    (65, 0): "F8",
    (81, 0): "DOWNARROW",
    (42, 0): "DELETE",
    (60, 0): "F3",
    (76, 0): "DEL",
    (77, 0): "END",
    (73, 0): "INSERT",
    (62, 0): "F5",
    (80, 0): "LEFTARROW",
    (79, 0): "RIGHTARROW",
    (78, 0): "PAGEDOWN",
    (72, 0): "PAUSE",
    (44, 0): "SPACE",
    (82, 0): "UPARROW",
    (68, 0): "F11",
    (64, 0): "F7",
    (83, 0): "KPNUMLOCK",
    (84, 0): "KP/",
    (85, 0): "KP*",
    (86, 0): "KP-",
    (87, 0): "KP+",
    (88, 0): "KPENTER",
    (89, 0): "KP1END",
    (90, 0): "KP2DOWNARROW",
    (91, 0): "KP3PAGEDOWN",
    (92, 0): "KP4LEFTARROW",
    (93, 0): "KP5",
    (94, 0): "KP6RIGHTARROW",
    (95, 0): "KP7HOME",
    (96, 0): "KP8UPARROW",
    (97, 0): "KP9PAGEUP",
    (98, 0): "KP0INSERT",
    (99, 0): "KP.DELETE",
    (101, 0): "APPLICATION",
    (103, 0): "KP=",
    (133, 0): "KP,",
    (134, 0): "KP=",
}

__all__ = [
    "HID_MAP",
    "HID_SPECIALS",
]
















