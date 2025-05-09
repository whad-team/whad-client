"""WHAD privacy tools.
"""
import os
import abc
import logging
from typing import Tuple, List, Dict, Union
from hashlib import sha512

from whad.settings import UserSettings

class PrivacySeed:

    value = None

    @staticmethod
    def get():
        if PrivacySeed.value is None:
            PrivacySeed.value = UserSettings().privacy_seed
        return PrivacySeed.value

class PrivateInfo(metaclass=abc.ABCMeta):
    """Abstract class for classes that store
    private information.
    """
    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'anonymize') and
                callable(subclass.anonymize))

    @abc.abstractmethod
    def anonymize(self, seed: int):
        """Anonymize the corresponding information
        before logging, using the specified seed.

        :return: A copy of the object that has been anonymized.
        """
        raise NotImplementedError

class PrivacyLogger:
    """Python standard logger wrapper class used to anonymize private information
    in order to avoid leaking any information that could be used to identify
    a person, machine or location.
    """

    def __init__(self, logger: logging.Logger):
        """Initialize our logger.
        """
        self.__logger = logger
        settings = UserSettings()
        self.__seed = settings.privacy_seed

    # Forwared other attributes to the underlying logger
    def __getattr__(self, name):
        if hasattr(self.__logger):
            return getattr(self.__logger)
        raise AttributeError

    def __anonymize_args(self, args, kwargs) -> Tuple[List, Dict]:
        """Anonymize args and keyword args
        """
        # If anonymization is turned off, return the same args and kwargs
        if "anonymized" not in os.environ:
            return (args, kwargs)

        # Loop on args and anonymize private information
        anon_args = []
        for arg in args:
            if isinstance(arg, PrivateInfo):
                anon_args.append(arg.anonymize(self.__seed))
            else:
                anon_args.append(arg)

        # Loop on kwargs
        anon_kwargs = {}
        for arg, value in kwargs.items():
            if isinstance(value, PrivateInfo):
                anon_kwargs[arg] = value.anonymize(self.__seed)
            else:
                anon_kwargs[arg] = value

        return (anon_args, anon_kwargs)

    def critical(self, msg, *args, **kwargs):
        """Anonymize critical message if required.
        """
        _args,_kwargs = self.__anonymize_args(args, kwargs)
        self.__logger.critical(msg, *_args, **_kwargs)

    def error(self, msg, *args, **kwargs):
        """Anonymize error message if required.
        """
        _args,_kwargs = self.__anonymize_args(args, kwargs)
        self.__logger.error(msg, *_args, **_kwargs)

    def warning(self, msg, *args, **kwargs):
        """Anonymize warning message if required.
        """
        _args,_kwargs = self.__anonymize_args(args, kwargs)
        self.__logger.warning(msg, *_args, **_kwargs)

    def info(self, msg, *args, **kwargs):
        """Anonymize info message if required.
        """
        _args,_kwargs = self.__anonymize_args(args, kwargs)
        self.__logger.info(msg, *_args, **_kwargs)

    def debug(self, msg, *args, **kwargs):
        """Anonymize debug message if required.
        """
        _args,_kwargs = self.__anonymize_args(args, kwargs)
        self.__logger.debug(msg, *_args, **_kwargs)


def anonymize(value: Union[str, bytes, PrivateInfo], seed: bytes):
    """Anonymization helper.

    This function takes a value and derives a new one from it,
    based on the provided seed.
    """
    if isinstance(value, bytes):
        size = len(value)
        anon_value = sha512(seed+value+seed).digest()
        while len(anon_value) < size:
            anon_value += sha512(seed+anon_value+seed).digest()
        return anon_value[:size]
    elif isinstance(value, PrivateInfo):
        return value.anonymize(seed)
    return value

def replace_bytes(buffer: bytes, needle: bytes, seed: bytes):
    """Replace a specific series of bytes in a byte byffer by its anonymized version.
    """
    try:
        pos = buffer.index(needle)
        replacement = anonymize(needle, seed)
        return buffer[:pos] + replacement + buffer[pos+len(needle):]
    except ValueError:
        return buffer

def print_safe(fmt: str, *args):
    """Anonymize parameters, format and print the specified message.

    :param fmt: Format string
    :type fmt: str
    :param args: Parameters to aninymize and pass to the format string
    :type args: list
    """
    # Retrieve user seed
    if "anonymized" not in os.environ:
        print(fmt % tuple(args))
    else:
        _args = [anonymize(arg, PrivacySeed.get()) for arg in args]
        print(fmt % tuple(_args))
