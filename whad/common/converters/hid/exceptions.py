class HIDLocaleNotFound(Exception):
    def __init__(self, locale):
        super().__init__()
        self.locale = locale

    def __str__(self):
        return 'HIDLocaleNotFound(%s)' % self.locale

    def __repr__(self):
        return str(self)


class HIDKeyNotFound(Exception):
    def __init__(self, key, ctrl, alt, shift, gui):
        self.key = key
        self.ctrl = ctrl
        self.alt = alt
        self.shift = shift
        self.gui = gui
        super().__init__()

    def __str__(self):
        return 'HIDKeyNotFound(key={}, ctrl={}, alt={}, shift={}, gui={})'.format(
            self.key,
            self.ctrl,
            self.alt,
            self.shift,
            self.gui
        )

    def __repr__(self):
        return str(self)


class HIDCodeNotFound(Exception):
    def __init__(self, hid_code, modifiers):
        self.modifiers = modifiers
        self.hid_code = hid_code
        super().__init__(self)


    def __str__(self):
        return 'HIDCodeNotFound(hid_code={}, modifiers={}))'.format(
            self.hid_code,
            self.modifiers
        )

    def __repr__(self):
        return str(self)
