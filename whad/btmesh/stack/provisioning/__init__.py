"""
BT Mesh Provisioning Layer (Provisioning Protocol, common to all Bearers)

Manages the actual exchange of information between the Provisioner and the Provisionee.
Implements both the Provisioner and Provisionee side.
"""

import logging

from whad.scapy.layers.btmesh import (
    BTMesh_Provisioning_Invite,
    BTMesh_Provisioning_Capabilities,
    BTMesh_Provisioning_Start,
    BTMesh_Provisioning_Public_Key,
    BTMesh_Provisioning_Input_Complete,
    BTMesh_Provisioning_Confirmation,
    BTMesh_Provisioning_Random,
    BTMesh_Provisioning_Data,
    BTMesh_Provisioning_Complete,
    BTMesh_Provisioning_Failed,
    BTMesh_Provisioning_Record_Request,
    BTMesh_Provisioning_Records_Get,
    BTMesh_Provisioning_Records_List,
    BTMesh_Provisioning_Record_Response,
    BTMesh_Provisioning_Hdr,
)
from scapy.packet import Packet
from whad.common.stack import Layer, alias, instance, state, LayerState
from whad.btmesh.stack.exceptions import (
    UnknownParameterValueSendError,
    FailedProvisioningReceivedError,
    UnknownProvisioningPacketTypeError,
    UncompatibleAlgorithmsAvailableError,
    InvalidConfirmationError,
)
from whad.btmesh.stack.constants import (
    NO_OOB_AUTH,
    STATIC_OOB_AUTH,
    OUTPUT_OOB_AUTH,
    OUTPUT_NUMERIC_AUTH,
    INPUT_NUMERIC_AUTH,
    INPUT_OOB_AUTH,
    PROVISIONING_TYPES,
)
from whad.btmesh.crypto import (
    ProvisioningBearerAdvCryptoManagerProvisioner,
    ProvisioningBearerAdvCryptoManagerProvisionee,
)
from whad.btmesh.stack.utils import (
    ProvisioningData,
    ProvisioningAuthenticationData,
)

from scapy.all import raw

logger = logging.getLogger(__name__)

_ALGS_FLAGS = {
    0x00: "BTM_ECDH_P256_CMAC_AES128_AES_CCM",
    0x01: "BTM_ECDH_P256_HMAC_SHA256_AES_CCM",
}


class ProvisioningState(LayerState):
    """
    State (DB) of the Provisioning layer, instance by the associated Generic Provisioner
    """

    def __init__(self):
        super().__init__()

        # The chosen parameters of the provisioning process
        self.chosen_parameters = dict(
            algorithms=0b10,  # default BTM_ECDH_P256_HMAC_SHA256_AES_CCM
            public_key_type=0x00,  # default no OOB public key
            authentication_method=0x00,  # no OOB auth default
            authentication_action=0x00,  # no OOB auth default
            authentication_size=0x00,
        )

        self.crypto_manager = None

        self.status = None

        self.auth_data = None

        self.next_expected_packet = None

        self.is_provisioning_started = False

        self.prov_data = ProvisioningData()


@state(ProvisioningState)
@alias("provisioning")
class ProvisioningLayer(Layer):
    """Provisioning Provisioner/Provisionee base class
    Since it is upper layer of Generic Provisioning Layer (instanced, ContextualLayer)
    This class and subclasses are used for one provisioning only.
    """

    def configure(self, options):
        """Configure the Provisioning Layer"""

        self._handlers = {
            BTMesh_Provisioning_Invite: self.on_invite,
            BTMesh_Provisioning_Capabilities: self.on_capabilities,
            BTMesh_Provisioning_Start: self.on_start,
            BTMesh_Provisioning_Public_Key: self.on_public_key,
            BTMesh_Provisioning_Input_Complete: self.on_input_complete,
            BTMesh_Provisioning_Confirmation: self.on_confirmation,
            BTMesh_Provisioning_Random: self.on_random,
            BTMesh_Provisioning_Data: self.on_data,
            BTMesh_Provisioning_Complete: self.on_complete,
            BTMesh_Provisioning_Failed: self.on_failed,
            BTMesh_Provisioning_Record_Request: self.on_record_request,
            BTMesh_Provisioning_Records_Get: self.on_records_get,
            BTMesh_Provisioning_Records_List: self.on_records_list,
            BTMesh_Provisioning_Record_Response: self.on_record_response,
        }

    def send_error_response(self, error_code):
        """Sends a BTMesh_Provisioning_Failed to other device. Error code defined in scapy layer"""
        if error_code < 0x1 or error_code > 0x09:
            raise UnknownParameterValueSendError(
                "BTMesh_Provisioning_Failed.error_code", error_code
            )
        self.send_to_gen_prov(BTMesh_Provisioning_Failed(error_code=error_code))

    def set_static_oob(self, value):
        """
        Sets the static oob value if user want to use it.
        can only be used before the provisioning has started, otherwise not taken into account

        :param value: The value to set
        :type value: int | str
        """
        if self.is_provisioning_started:
            return
        self.state.auth_data = ProvisioningAuthenticationData(
            auth_method=STATIC_OOB_AUTH, auth_action=None, value=value
        )

    def send_to_gen_prov(self, packet):
        hdr = BTMesh_Provisioning_Hdr(
            type=PROVISIONING_TYPES[type(packet)], message=packet
        )
        self.send("gen_prov", hdr)

    def set_profile(self, profile):
        """
        Sets the profile object of our node to be able to access it from this layer

        :param profile: The profile object of our node
        :type profile: BTMeshProfile
        """
        self.state.profile = profile

    @instance("gen_prov")
    def on_packet_received(self, source, packet):
        """Process incoming packets from the Generic Provisioning Layer"""

        # If Provisioning Packet, retreive payload from Hdr
        if isinstance(packet, BTMesh_Provisioning_Hdr):
            packet = packet.message

        packet_type = type(packet)

        if (
            packet_type not in self._handlers
            or packet_type is not self.state.next_expected_packet
            and packet_type is not BTMesh_Provisioning_Failed
        ):
            logger.debug(
                "Received unexpected packet in Provisioning layer : :%s" % packet_type
            )
            raise UnknownProvisioningPacketTypeError(packet_type)
        self._handlers[packet_type](packet)

        # All handlers except Failed return errors here since we are in the generic layer. Needs implement in Provisioner/Provisionee classes.

    def on_failed(self, packet):
        raise FailedProvisioningReceivedError(packet.error_code)

    def on_invite(self, packet):
        self.send_error_response(0x07)

    def on_start(self, packet):
        self.send_error_response(0x07)

    def on_capabilities(self, packet):
        self.send_error_response(0x07)

    def on_provisioning_auth_data(self, packet):
        self.send_error_response(0x07)

    def on_public_key(self, packet):
        """
        On receiving Peer Public Key
        Same first actions for Provisioner and Provisionee. See subclasses for the rest
        """
        pub_key_x = packet.public_key_x
        pub_key_y = packet.public_key_y

        self.state.crypto_manager.add_peer_public_key(pub_key_x, pub_key_y)

        # compute ECDH secret
        self.state.crypto_manager.compute_ecdh_secret()

        # compute Confirm0b01000ation Salt, and confirmation key, and generate random value
        self.state.crypto_manager.compute_confirmation_salt(
            self.state.invite_pdu, self.state.capabilities_pdu, self.state.start_pdu
        )
        self.state.crypto_manager.generate_random()

    def on_input_complete(self, packet):
        self.send_error_response(0x07)

    def on_confirmation(self, packet):
        self.send_error_response(0x07)

    def on_random(self, packet):
        self.send_error_response(0x07)

    def on_data(self, packet):
        self.send_error_response(0x07)

    def on_complete(self, packet):
        self.send_error_response(0x07)

    def on_record_request(self, packet):
        self.send_error_response(0x07)

    def on_records_get(self, packet):
        self.send_error_response(0x07)

    def on_records_list(self, packet):
        self.send_error_response(0x07)

    def on_record_response(self, packet):
        self.send_error_response(0x07)

    def on_ack(self, message):
        pass


class ProvisioningLayerProvisioner(ProvisioningLayer):
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    def configure(self, options):
        super().configure(options)

    def initiate_provisioning(self):
        """
        When Unprovisoned Beacon received and we choose to provision, send invite
        """

        self.state.is_provisioning_started = True

        invite_packet = BTMesh_Provisioning_Invite(attention_duration=100)
        # store for Confirmation Inputs
        self.state.invite_pdu = raw(invite_packet)
        self.send_to_gen_prov(invite_packet)

        self.state.next_expected_packet = BTMesh_Provisioning_Capabilities

    def on_capabilities(self, packet):
        """
        Retrieve capabilities of Provisionee to choose what we want
        (for now static choice)
        Send Start pdu after
        """

        self.state.prov_data.addr_range = packet.number_of_elements

        # store for Confirmation inputs
        self.state.capabilities_pdu = raw(packet)
        own_capabilities = self.get_layer("pb_adv").state.connector.profile.capabilities

        if packet.algorithms & 0b10 and own_capabilities["algorithms"] & 0b10:
            self.state.chosen_parameters["algorithms"] = 0x01
        elif packet.algorithms & 0b01 and own_capabilities["algorithms"] & 0b01:
            self.state.chosen_parameters["algorithms"] = 0x00
        else:
            raise UncompatibleAlgorithmsAvailableError

        if (
            packet.output_oob_size != 0
            and own_capabilities["output_oob_size"] != 0
            and packet.output_oob_action & 0b11000 != 0
            and own_capabilities["output_oob_action"] & 0b11000
        ):
            self.state.chosen_parameters["authentication_method"] = OUTPUT_OOB_AUTH
            self.state.chosen_parameters["authentication_action"] = OUTPUT_NUMERIC_AUTH
            self.state.chosen_parameters["authentication_size"] = max(
                packet.output_oob_size, own_capabilities["output_oob_size"]
            )

        elif (
            packet.input_oob_size != 0
            and own_capabilities["input_oob_size"] != 0
            and packet.input_oob_action & 0b1100
            and own_capabilities["input_oob_action"] & 0b1100
        ):
            self.state.chosen_parameters["authentication_method"] = INPUT_OOB_AUTH
            self.state.chosen_parameters["authentication_action"] = INPUT_NUMERIC_AUTH
            self.state.chosen_parameters["authentication_size"] = max(
                packet.input_oob_size, own_capabilities["input_oob_size"]
            )

        # the rest is static for now, already set in state init
        params = self.state.chosen_parameters

        start_packet = BTMesh_Provisioning_Start(
            algorithms=params["algorithms"],
            public_key_type=params["public_key_type"],
            authentication_method=params["authentication_method"],
            authentication_action=params["authentication_action"],
            authentication_size=params["authentication_size"],
        )

        # store for Confirmation Inputs
        self.state.start_pdu = raw(start_packet)
        self.send_to_gen_prov(start_packet)

        self.state.crypto_manager = ProvisioningBearerAdvCryptoManagerProvisioner(
            alg=_ALGS_FLAGS[params["algorithms"]]
        )

        # generate keys
        self.state.crypto_manager.generate_keypair()

        # Send our public key to provisionee
        self.send_to_gen_prov(
            BTMesh_Provisioning_Public_Key(
                public_key_x=self.state.crypto_manager.public_key_coord_provisioner[0],
                public_key_y=self.state.crypto_manager.public_key_coord_provisioner[1],
            )
        )

        # If auth is needed
        if start_packet.authentication_method != NO_OOB_AUTH:
            self.state.auth_data = ProvisioningAuthenticationData(
                auth_method=start_packet.authentication_method,
                auth_action=start_packet.authentication_action,
                size=start_packet.authentication_size,
            )
        else:
            self.state.auth_data = None

        self.state.next_expected_packet = BTMesh_Provisioning_Public_Key

    def on_public_key(self, packet):
        """
        On receiving Provisionee Public Key.
        """
        super().on_public_key(packet)

        # if we need auth data, do what is necessary
        if self.state.auth_data is not None:
            if self.state.auth_data == STATIC_OOB_AUTH:
                self.state.crypto_manager.set_auth_value(self.state.auth_data.value)
                # Compute Confirmation Provisioner Value and send it
                self.state.crypto_manager.compute_confirmation_key()
                self.state.crypto_manager.compute_confirmation_provisioner()
                self.send_to_gen_prov(
                    BTMesh_Provisioning_Confirmation(
                        self.state.crypto_manager.confirmation_provisioner
                    )
                )
                self.state.next_expected_packet = BTMesh_Provisioning_Confirmation

            # If input oob, we wait for the BTMesh_Provisioning_Input_Complete packet from provisionee (and we actually need to output it)
            # we also generate the value here (only numeric or alphanum supported)
            elif self.state.auth_data.auth_method == INPUT_OOB_AUTH:
                self.state.auth_data.generate_value()
                self.state.crypto_manager.set_auth_value(self.state.auth_data.value)
                self.state.next_expected_packet = BTMesh_Provisioning_Input_Complete

                # get connector to notify the need for auth
                self.get_layer("pb_adv").state.connector.provisioning_auth_data(
                    self.state.auth_data
                )

            elif self.state.auth_data.auth_method == OUTPUT_OOB_AUTH:

                self.get_layer("pb_adv").state.connector.provisioning_auth_data(
                    self.state.auth_data
                )
                self.state.next_expected_packet = None

        else:
            # Compute Confirmation Provisioner Value and send it
            self.state.crypto_manager.compute_confirmation_key()
            self.state.crypto_manager.compute_confirmation_provisioner()
            self.send_to_gen_prov(
                BTMesh_Provisioning_Confirmation(
                    self.state.crypto_manager.confirmation_provisioner
                )
            )
            self.state.next_expected_packet = BTMesh_Provisioning_Confirmation

    def on_provisioning_auth_data(self, auth_data):
        """
        Process a ProvisioningAuthenticationData received from the user that typed the OOB auth value
        (sent by connector directly)

        :param auth_data: The auth data
        :type auth_data: ProvisioningAuthenticationData
        """
        if auth_data.auth_method != OUTPUT_OOB_AUTH:
            return
        self.state.auth_data = auth_data
        self.state.crypto_manager.set_auth_value(self.state.auth_data.value)

        # Send the Confirmation Provisoner
        self.state.crypto_manager.compute_confirmation_key()
        self.state.crypto_manager.compute_confirmation_provisioner()
        self.send_to_gen_prov(
            BTMesh_Provisioning_Confirmation(
                self.state.crypto_manager.confirmation_provisioner
            )
        )
        self.state.next_expected_packet = BTMesh_Provisioning_Confirmation

    def on_input_complete(self, packet):
        """
        Process an Input Confirmation packet from the Provisionee when Input OOB is used.
        Sends the Confirmation packet.

        :param packet: [TODO:description]
        :type packet: [TODO:type]
        """
        self.state.crypto_manager.compute_confirmation_key()
        self.state.crypto_manager.compute_confirmation_provisioner()
        self.send_to_gen_prov(
            BTMesh_Provisioning_Confirmation(
                self.state.crypto_manager.confirmation_provisioner
            )
        )
        self.state.next_expected_packet = BTMesh_Provisioning_Confirmation

    def on_confirmation(self, packet):
        """
        Process a Confirmation packet from the Provisionee. Stores it for later verification.
        Sends the random value used for the Provisioner Confirmation computation.

        :param packet: [TODO:description]
        :type packet: [TODO:type]
        """
        self.state.crypto_manager.received_confirmation_provisionee = (
            packet.confirmation
        )

        self.send_to_gen_prov(
            BTMesh_Provisioning_Random(
                random=self.state.crypto_manager.rand_provisioner
            )
        )
        self.state.next_expected_packet = BTMesh_Provisioning_Random

    def on_random(self, packet):
        """
        Process the random packet from provisionee. Verifies the confirmation value previouly received.

        :param packet: [TODO:description]
        :type packet: [TODO:type]
        """
        self.state.crypto_manager.rand_provisionee = packet.random

        # compute confirmation provisionee and verifies if it matches received one
        self.state.crypto_manager.compute_confirmation_provisionee()

        if (
            self.state.crypto_manager.received_confirmation_provisionee
            != self.state.crypto_manager.confirmation_provisionee
        ):
            raise InvalidConfirmationError

        # Compute session nonce and and key
        self.state.crypto_manager.compute_provisioning_salt()
        self.state.crypto_manager.compute_session_key()
        self.state.crypto_manager.compute_session_nonce()

        # encrypt Provisioning Data payload
        # from sample data Spec p. 713
        # ""bytes.fromhex("efb2255e6422d330088e09bb015ed707056700010203040b0c")
        # plaintext = bytes.fromhex("efb2255e6422d330088e09bb015ed707056700010203040b0c")
        self.get_layer("pb_adv").state.connector.get_prov_data(
            prov_data=self.state.prov_data
        )

        # plaintext = bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00000000000000000003")
        plaintext = self.state.prov_data.get_data_string()
        cipher, mic = self.state.crypto_manager.encrypt(plaintext)

        # send provisioning Data to provisionee
        self.send_to_gen_prov(
            BTMesh_Provisioning_Data(
                encrypted_provisioning_data=cipher, provisioning_data_mic=mic
            )
        )
        self.state.next_expected_packet = BTMesh_Provisioning_Complete

    def on_complete(self, packet):
        """
        On receiving Provisionee Complete packet
        """
        # notify gen_prov to close the link
        self.get_layer("gen_prov").close_link()

        # Send the information of the new distant node to be stored to the profile
        self.get_layer("pb_adv").state.connector.on_provisioning_complete(
            self.state.prov_data
        )


class ProvisioningLayerProvisionee(ProvisioningLayer):
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)

        self.state.next_expected_packet = BTMesh_Provisioning_Invite

    def configure(self, options):
        super().configure(options)

    def on_invite(self, packet):
        """
        Responds to an invite to connect to network with capablities
        """
        self.state.is_provisioning_started = True
        capabilities = self.get_layer("pb_adv").state.connector.profile.capabilities

        # store for Confirmation Inputs
        self.state.invite_pdu = raw(packet)
        capabilities_packet = BTMesh_Provisioning_Capabilities(**capabilities)
        self.send_to_gen_prov(capabilities_packet)
        # store for Confirmation Inputs
        self.state.capabilities_pdu = raw(capabilities_packet)
        self.state.next_expected_packet = BTMesh_Provisioning_Start

    def on_start(self, packet):
        """
        Process a received Provisioning Start Packet. Retrives chosen parameters and creates crypto manager
        Static OOB not supported ! (dont set it in capabilities...)
        """
        self.state.chosen_parameters["algorithms"] = packet.algorithms

        auth_method = packet.authentication_method
        auth_action = packet.authentication_action
        size = packet.authentication_size

        if auth_method == INPUT_OOB_AUTH or auth_method == OUTPUT_OOB_AUTH:
            self.state.auth_data = ProvisioningAuthenticationData(
                auth_method=auth_method, auth_action=auth_action, size=size
            )

        # if static OOB needed and we have none, we fail
        elif auth_method == STATIC_OOB_AUTH and self.state.auth_data is None:
            self.send_to_gen_prov(BTMesh_Provisioning_Failed(0x07))
            self.state.next_expected_packet = None
            return

        elif auth_method == NO_OOB_AUTH:
            self.state.auth_data = None

        self.state.crypto_manager = ProvisioningBearerAdvCryptoManagerProvisionee(
            alg=_ALGS_FLAGS[self.state.chosen_parameters["algorithms"]],
        )

        # store the PDU to compute Confirmation Inputs
        self.state.start_pdu = raw(packet)
        self.state.next_expected_packet = BTMesh_Provisioning_Public_Key

    def on_public_key(self, packet):
        """
        Process the Provisoner Public Key by storing it and send the provisionee public key

        :param packet: [TODO:description]
        :type packet: [TODO:type]
        """

        self.state.crypto_manager.generate_keypair()

        super().on_public_key(packet)

        self.send_to_gen_prov(
            BTMesh_Provisioning_Public_Key(
                public_key_x=self.state.crypto_manager.public_key_coord_provisionee[0],
                public_key_y=self.state.crypto_manager.public_key_coord_provisionee[1],
            )
        )

        # if we need auth data, do what is necessary
        if self.state.auth_data is not None:
            if self.state.auth_data == STATIC_OOB_AUTH:
                self.state.crypto_manager.set_auth_value(self.state.auth_data.value)
                self.state.next_expected_packet = BTMesh_Provisioning_Confirmation

            # If input oob, we notify user that it needs to input it.
            elif self.state.auth_data.auth_method == INPUT_OOB_AUTH:
                self.get_layer("pb_adv").state.connector.provisioning_auth_data(
                    self.state.auth_data
                )
                self.state.next_expected_packet = None

            # If output oob, we need to output it (thus generate it)
            elif self.state.auth_data.auth_method == OUTPUT_OOB_AUTH:
                self.state.auth_data.generate_value()
                self.state.crypto_manager.set_auth_value(self.state.auth_data.value)
                self.get_layer("pb_adv").state.connector.provisioning_auth_data(
                    self.state.auth_data
                )
                self.state.next_expected_packet = BTMesh_Provisioning_Confirmation

        else:
            self.state.next_expected_packet = BTMesh_Provisioning_Confirmation

    def on_provisioning_auth_data(self, auth_data):
        """
        Process a ProvisioningAuthenticationData received from the used that typed the OOOB auth value
        (sent by connector directly)

        :param auth_data: The auth data
        :type auth_data: ProvisioningAuthenticationData
        """
        if auth_data.auth_method != INPUT_OOB_AUTH:
            return
        self.state.auth_data = auth_data
        self.state.crypto_manager.set_auth_value(self.state.auth_data.value)

        self.send_to_gen_prov(BTMesh_Provisioning_Input_Complete())
        self.state.next_expected_packet = BTMesh_Provisioning_Confirmation

    def on_confirmation(self, packet):
        """
        Process a Confirmation packet from the Provisioner. Stores the value for later verification and sends provisionee Confirmation

        :param packet: [TODO:description]
        :type packet: [TODO:type]
        """
        self.state.crypto_manager.received_confirmation_provisioner = (
            packet.confirmation
        )

        self.state.crypto_manager.compute_confirmation_key()
        self.state.crypto_manager.compute_confirmation_provisionee()
        self.send_to_gen_prov(
            BTMesh_Provisioning_Confirmation(
                confirmation=self.state.crypto_manager.confirmation_provisionee
            )
        )
        self.state.next_expected_packet = BTMesh_Provisioning_Random

    def on_random(self, packet):
        """
        Process a Confirmation packet from the Provisioner. Verify the confirmation provisioner value with it
        Sends the random value used for the Provisionee Confirmation computation.

        :param packet: [TODO:description]
        :type packet: [TODO:type]
        """
        self.state.crypto_manager.rand_provisioner = packet.random

        # verification of previoulsy received confirmation value
        self.state.crypto_manager.compute_confirmation_provisioner()

        if (
            self.state.crypto_manager.received_confirmation_provisioner
            != self.state.crypto_manager.confirmation_provisioner
        ):
            raise InvalidConfirmationError

        # send provisionee random value

        self.send_to_gen_prov(
            BTMesh_Provisioning_Random(self.state.crypto_manager.rand_provisionee)
        )

        self.state.next_expected_packet = BTMesh_Provisioning_Data

    def on_data(self, packet):
        """
        Process a Provisioning Data sent by the provisioner. Decypher it and stores the keys

        :param packet: [TODO:description]
        :type packet: [TODO:type]
        """

        # Compute session key and nonce first
        self.state.crypto_manager.compute_provisioning_salt()
        self.state.crypto_manager.compute_session_key()
        self.state.crypto_manager.compute_session_nonce()

        # Get fields from packet
        cipher = packet.encrypted_provisioning_data
        mic = packet.provisioning_data_mic

        plaintext, verify = self.state.crypto_manager.decrypt(cipher, mic)
        net_key = plaintext[:16]
        key_index = plaintext[16:18]
        flags = plaintext[18:19]
        iv_index = plaintext[19:23]
        unicast_addr = plaintext[23:]

        self.state.prov_data.net_key = net_key
        self.state.prov_data.key_index = int.from_bytes(key_index, "big")
        self.state.prov_data.flags = flags
        self.state.prov_data.iv_index = iv_index
        self.state.prov_data.unicast_addr = int.from_bytes(unicast_addr, "big")
        self.state.prov_data.provisioning_crypto_manager = self.state.crypto_manager

        logger.debug("NetworkKey = " + plaintext[:16].hex())
        logger.debug("KeyIndex = " + plaintext[16:18].hex())
        logger.debug("Flags = " + plaintext[18:19].hex())
        logger.debug("IV Index = " + plaintext[19:23].hex())
        logger.debug("UnicastAddr = " + plaintext[23:].hex())

        # send complete
        self.send_to_gen_prov(BTMesh_Provisioning_Complete())
        self.get_layer("pb_adv").state.connector.provisioning_complete(prov_data)
        self.state.next_expected_packet = None
