class HIDLocaleNotFound(Exception):
    def __init__(self, locale):
        super().__init__()
        self.locale = locale

class HIDKeyNotFound(Exception):
    def __init__(self, key, ctrl, alt, shift, gui):
        self.key = key
        self.ctrl = ctrl
        self.alt = alt
        self.shift = shift
        self.gui = gui
        super().__init__()

class HIDCodeNotFound(Exception):
    def __init__(self, hid_code, modifiers):
        super().__init__(self)
        self.modifiers = modifiers
        self.hid_code = hid_code
