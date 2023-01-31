"""
Logitech Unifying applicative layer.
"""
from whad.scapy.layers.unifying import Logitech_Unifying_Hdr, Logitech_Mouse_Payload, Logitech_Set_Keepalive_Payload, \
    Logitech_Keepalive_Payload, Logitech_Unencrypted_Keystroke_Payload, Logitech_Encrypted_Keystroke_Payload, \
    Logitech_Multimedia_Key_Payload
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter, LogitechUnifyingKeystrokeConverter, InvalidHIDData
from whad.unifying.stack.constants import UnifyingRole, ClickType, MultimediaKey
from whad.unifying.crypto import LogitechUnifyingCryptoManager
from time import sleep, time
from threading import Thread, Lock
from queue import Queue, Empty

class UnifyingApplicativeLayerManager:
    """
    This class handles the logic of Logitech Unifying protocol, used by Logitech mices and keyboards.
    The protocol is an application layer built over the Enhanced ShockBurst protocol, provided by Nordic SemiConductors.
    """
    def __init__(self, llm, role=UnifyingRole.DONGLE):
        self.__llm = llm
        self.__role = role
        self.__locale = "fr"
        self.__transmit_timeouts = False
        self.__timeout_thread = None
        self.__crypto_manager = None
        self.__aes_counter = 0
        self.__packets_queue = Queue(5)

    @property
    def aes_counter(self):
        return self.__aes_counter

    @aes_counter.setter
    def aes_counter(self, counter):
        self.__aes_counter = counter

    @property
    def locale(self):
        return self.__locale

    @locale.setter
    def locale(self, value):
        self.__locale = value

    def _start_timeout_thread(self):
        self._stop_timeout_thread()
        self.__transmit_timeouts = True
        self.__timeout_thread = Thread(target=self._transmit_timeouts_thread, daemon=True)
        self.__timeout_thread.start()

    def _stop_timeout_thread(self):
        if self.__timeout_thread is not None:
            self.__transmit_timeouts = False
            self.__timeout_thread.join()
            self.__timeout_thread = None

    def _transmit_timeouts_thread(self):
        keep_alive_count = 0
        self.send_message(Logitech_Set_Keepalive_Payload(timeout=1250))
        last_send = time()
        while self.__transmit_timeouts:
            if time() - last_send >= 0.001:
                if keep_alive_count % 10 == 0:
                    self.send_message(Logitech_Set_Keepalive_Payload(timeout=1250))
                else:
                    self.send_message(Logitech_Keepalive_Payload(timeout=1250))
                    keep_alive_count += 1
                last_send = time()

            try:
                packet = self.__packets_queue.get(block=False)
                self.send_message(Logitech_Set_Keepalive_Payload(timeout=1250))
                self.send_message(packet)
                self.send_message(Logitech_Keepalive_Payload(timeout=1250))
            except Empty:
                pass

    def send_message(self, message, waiting_ack=False):
        result = self.__llm.send_data(Logitech_Unifying_Hdr()/message, waiting_ack=waiting_ack)
        return result

    def prepare_message(self, message):
        self.__packets_queue.put(message)
        return True

    def __del__(self):
        self._stop_timeout_thread()

    @property
    def role(self):
        return self.__role

    @role.setter
    def role(self, role):
        self.__role = role

    @property
    def key(self):
        if self.__crypto_manager is not None:
            return self.__crypto_manager.key
        else:
            return None

    @key.setter
    def key(self, key):
        if self.__crypto_manager is None or self.__crypto_manager.key != key:
            if key is not None:
                self.__crypto_manager = LogitechUnifyingCryptoManager(key)
            else:
                self.__crypto_manager = None

    def enable_timeouts(self):
        if self.__role == UnifyingRole.DONGLE:
            raise RequiredImplementation("WaitingKeepAlives")
        else:
            self._start_timeout_thread()

    def lock_channel(self):
        if self.__timeout_thread is None:
            self.enable_timeouts()

    def move_mouse(self, x, y):
        self.lock_channel()
        try:
            answer = self.prepare_message(
                Logitech_Mouse_Payload(
                    movement=LogitechUnifyingMouseMovementConverter.get_hid_data_from_coordinates(x, y)
                )
            )
            sleep(0.001)
            return answer
        except InvalidHIDData:
            return False

    def click_mouse(self, type=ClickType.RIGHT):
        self.lock_channel()
        answer = self.prepare_message(
            Logitech_Mouse_Payload(
                button_mask=int(type)
            )

        )
        return answer

    def wheel_mouse(self, x, y):
        self.lock_channel()
        answer = self.prepare_message(
            Logitech_Mouse_Payload(
                button_mask=0,
                movement='',
                wheel_x=x,
                wheel_y=y
            )

        )
        return answer

    def unencrypted_keystroke(self, key, ctrl=False, alt=False, shift=False, gui=False):
        self.lock_channel()
        try:
            answer_press = self.prepare_message(
                Logitech_Unencrypted_Keystroke_Payload(
                    hid_data=LogitechUnifyingKeystrokeConverter.get_hid_data_from_key(
                        key,
                        ctrl=False,
                        alt=False,
                        shift=False,
                        gui=False,
                        locale=self.__locale
                    )
                )
            )

            answer_release = self.prepare_message(
                Logitech_Unencrypted_Keystroke_Payload(
                    hid_data=b"\x00"*7
                )
            )

            return answer_press and answer_release

        except InvalidHIDData:
            return False

    def multimedia_keystroke(self,key):
        self.lock_channel()
        try:
            answer_press = self.prepare_message(
                Logitech_Multimedia_Key_Payload(
                    hid_key_scan_code=b"x\00"+bytes([int(key)])+b"\x00"*2
                )
            )
            answer_release = self.prepare_message(
                Logitech_Multimedia_Key_Payload(
                    hid_key_scan_code=b"\x00"*4
                )
            )

            return answer_press and answer_release

        except InvalidHIDData:
            return False


    def encrypted_keystroke(self, key, ctrl=False, alt=False, shift=False, gui=False, force_counter=None):
        if self.__crypto_manager is None:
            return False

        counter = self.aes_counter if force_counter is None else force_counter

        self.lock_channel()
        try:
            answer_press = self.prepare_message(
                self.__crypto_manager.encrypt(
                    Logitech_Encrypted_Keystroke_Payload(
                        hid_data=LogitechUnifyingKeystrokeConverter.get_hid_data_from_key(
                            key,
                            ctrl=False,
                            alt=False,
                            shift=False,
                            gui=False,
                            locale=self.__locale
                        ),
                        unknown=201,
                        aes_counter=counter
                    ),
                    acknowledged=False
                )
            )
            answer_release = self.prepare_message(
                self.__crypto_manager.encrypt(

                    Logitech_Encrypted_Keystroke_Payload(
                        hid_data=b"\x00"*7,
                        unknown=201,
                        aes_counter=counter+1
                    )
                ),
                acknowledged=False
            )

            if force_counter is None:
                self.aes_counter += 2

            return answer_press and answer_release
        except InvalidHIDData:
            return False


    def on_synchronized(self):
        print("[i] Synchronized !")
        self.lock_channel()


    def on_desynchronized(self):
        print("[i] Desynchronized, resync...")

    def on_data(self, data):
        pass

    def on_acknowledgement(self, ack):
        print("acked")
