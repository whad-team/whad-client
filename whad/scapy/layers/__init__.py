"""Import all known layers by default

This can be useful if you plan to read or write PCAP packets as DLT are also
declared in these submodules.
"""
from .dot15d4tap import *
from .nordic import *
