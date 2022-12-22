from whad.ble.stack.att.exceptions import AttError, AttributeNotFoundError, \
    InsufficientAuthenticationError, InsufficientAuthorizationError, \
    InsufficientEncryptionKeySize, ReadNotPermittedError, \
    WriteNotPermittedError, InvalidHandleValueError

def show_att_error(app, error: AttError):
    """Parse ATT error and show exception.
    """
    if isinstance(error, InvalidHandleValueError):
        app.error('ATT Error: wrong value handle')
    elif isinstance(error, ReadNotPermittedError):
        app.error('ATT error: read operation not allowed')
    elif isinstance(error, WriteNotPermittedError):
        app.error('ATT error: write operation not allowed')
    elif isinstance(error, InsufficientAuthenticationError):
        app.error('ATT error: insufficient authentication')
    elif isinstance(error, InsufficientAuthorizationError):
        app.error('ATT error: insufficient authorization')
    elif isinstance(error, AttributeNotFoundError):
        app.error('ATT error: attribute not found')
    elif isinstance(error, InsufficientEncryptionKeySize):
        app.error('ATT error: insufficient encryption')