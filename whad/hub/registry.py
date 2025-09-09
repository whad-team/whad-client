"""WHAD Protocol hub Registry

This module implements the Registry class used in automated protocol buffers
messages parsing.
"""
from .exceptions import UnsupportedVersionException

class Registry:
    """Protocol message versions registry.
    """

    VERSIONS = {}
    NAME = None

    @classmethod
    def add_node_version(parent_class, version: int, name: str, clazz):
        """Add a specific class `clazz` to our message registry for version
        `version` with alias `name`.
        """
        # If version is unknown, create it
        if version not in parent_class.VERSIONS:
            parent_class.VERSIONS[version] = {}

        # Add clazz based on provided alias for this version
        parent_class.VERSIONS[version][name] = clazz

    @classmethod
    def bound(cls, name: str = None, version: int = 1):
        """Retrieve the given node class `name` for version `version`.

        If there is no defined class for version N, look for a corresponding
        class in version N-1, N-2 until 0.
        """
        # Look for node class from given name and version
        if version in cls.VERSIONS:
            if name in cls.VERSIONS[version]:
                return cls.VERSIONS[version][name]

        if version > 1:
            # If not found for version N, look for node class in version N-1
            return cls.bound(name, version - 1)

        # If not found, raise exception
        raise UnsupportedVersionException(name, version)
