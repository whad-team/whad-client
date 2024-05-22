from whad.ble.stack.smp.exceptions import SMInvalidCustomFunction
from whad.ble.stack.smp.constants import IOCAP_KEYBD_ONLY, IOCAP_DISPLAY_ONLY, \
    IOCAP_DISPLAY_YESNO, IOCAP_KEYBD_DISPLAY, IOCAP_NOINPUT_NOOUTPUT

class Pairing:
    def __init__(
        self,
        oob=False,
        bonding=True,
        mitm=False,
        lesc=True,
        keypress=False,
        ct2=False,
        max_key_size=16,
        iocap=IOCAP_NOINPUT_NOOUTPUT,
        enc_key=True,
        id_key=True,
        sign_key=True,
        link_key=True,
        accept_pairing=True,
        custom_functions=None
    ):
        self.oob = oob
        self.bonding = bonding
        self.mitm = mitm
        self.lesc = lesc
        self.keypress = keypress
        self.ct2 = ct2
        self.max_key_size = max_key_size
        self.iocap = iocap
        self.enc_key = enc_key
        self.id_key = id_key
        self.sign_key = sign_key
        self.link_key = link_key
        self.accept_pairing = accept_pairing
        self.custom_functions = custom_functions


class PairingCustomFunctions:
    def __init__(self,
            check_initiator_legacy_confirm = None,
            check_responder_legacy_confirm = None,
            compute_exchange_value = None,
            compute_ltk_and_mackey = None,
            compute_lesc_numeric_comparison = None,
            check_lesc_confirm_value = None,
            compute_lesc_confirm_value = None,
            compute_legacy_confirm_value = None,
            check_lesc_numeric_comparison = None,
            generate_p256_keypair = None,
            generate_legacy_ltk = None,
            generate_legacy_random = None,
            generate_legacy_ediv = None,
            generate_irk = None,
            generate_csrk = None,
            get_passkey_entry = None,
            get_pin_code = None
    ):
        self.check_initiator_legacy_confirm = check_initiator_legacy_confirm
        self.check_responder_legacy_confirm = check_responder_legacy_confirm
        self.compute_exchange_value = compute_exchange_value
        self.compute_ltk_and_mackey = compute_ltk_and_mackey
        self.compute_lesc_numeric_comparison = compute_lesc_numeric_comparison
        self.check_lesc_confirm_value = check_lesc_confirm_value
        self.compute_lesc_confirm_value = compute_lesc_confirm_value
        self.compute_legacy_confirm_value = compute_legacy_confirm_value
        self.check_lesc_numeric_comparison = check_lesc_numeric_comparison
        self.generate_p256_keypair = generate_p256_keypair
        self.generate_legacy_ltk = generate_legacy_ltk
        self.generate_legacy_random = generate_legacy_random
        self.generate_legacy_ediv = generate_legacy_ediv
        self.generate_irk = generate_irk
        self.generate_csrk = generate_csrk
        self.get_passkey_entry = get_passkey_entry
        self.get_pin_code = get_pin_code
