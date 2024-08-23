"""
Classes used between layers to manage a message.
"""

class MeshMessageContext:
    def __init__(self):
        self.net_crypto_manager = None
        self.app_crypto_manager = None

        self.src_addr = None
        self.dest_addr = None

        # If src_addr is Virtual Addr
        self.uuid = None

        # Either received TTL or sending TTL
        self.ttl = None

        # Either received RSSI or sending RSSI
        self.rssi = None
