from whad.common.stack import LayerState

class Dot15d4Database(LayerState):
    """
    802.15.4 Generic Database of attributes.
    """
    def __init__(self):
        super().__init__()
        self.reset()

    def reset(self):
        """
        Reset the PIB database to its default value.
        """
        pass

    def get(self, attribute):
        """
        Read a given database attribute.
        """
        if hasattr(self, attribute):
            return getattr(self, attribute)
        return None

    def set(self, attribute, value):
        """
        Write a value to a given database attribute.
        """
        if hasattr(self, attribute):
            setattr(self, attribute, value)
            return True
        return False
