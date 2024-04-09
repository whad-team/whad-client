"""ProtocolHub exceptions
"""

class UnsupportedVersionException(Exception):
    """Exception raised when a ProtocolHub registry node cannot be found.
    """

    def __init__(self, name: str, version: int):
        """Create a UnsupportedVersionException object, keeps track of name and
        version.
        """
        super().__init__()
        self.__name = name
        self.__version = version

    def __repr__(self):
        """Exception string.
        """
        return f'UnsupportedVersionException(name={self.__name}, version={self.__version})'