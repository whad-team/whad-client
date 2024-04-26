"""RF4CE Application Layer (APL) exceptions
"""

class APLTimeoutException(Exception):
    """This exception is raised when a timeout occurs at APL level.
    """
    def __init__(self):
        super().__init__()
