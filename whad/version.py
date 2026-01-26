"""This file contains the current version number of WHAD.

ATTENTION: This version number must match the one in pyproject.toml !
"""

# Current version number
VERSION_MAJOR = 1
VERSION_MINOR = 2
VERSION_REVISION = 12

def get_version() -> str:
    """Return the current version of this package (WHAD).

    @retval         current version string
    @return-type    str
    """
    return f"{VERSION_MAJOR:d}.{VERSION_MINOR:d}.{VERSION_REVISION:d}"
