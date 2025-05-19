"""
Message from PB_ADV Layer to Generic Provisioning.
It contains the Generic Provisioning Packet AND the transaction_number (since it's in the PB-ADV pdu for some reason ...)
"""


class GenericProvisioningMessage(object):
    def __init__(self, gen_prov_pkt, transaction_number):
        super().__init__()
        self.gen_prov_pkt = gen_prov_pkt
        self.transaction_number = transaction_number
