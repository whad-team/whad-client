"""
Logitech Unifying applicative layer.
"""
from whad.esb.stack.llm.constants import ESBRole
from whad.scapy.layers.unifying import Logitech_Unifying_Hdr, Logitech_Mouse_Payload, Logitech_Set_Keepalive_Payload, \
    Logitech_Keepalive_Payload, Logitech_Unencrypted_Keystroke_Payload, Logitech_Encrypted_Keystroke_Payload, \
    Logitech_Multimedia_Key_Payload, Logitech_Waked_Up_Payload, Logitech_Wake_Up_Payload
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter, LogitechUnifyingKeystrokeConverter, \
    HIDCodeNotFound, InvalidHIDData
from whad.unifying.stack.constants import UnifyingRole, ClickType, MultimediaKey
from whad.unifying.crypto import LogitechUnifyingCryptoManager
from whad.unifying.exceptions import MissingEncryptedKeystrokePayload
from whad.exceptions import WhadDeviceDisconnected, WhadDeviceTimeout
from whad.common.stack import Layer, alias, source, state, LayerState
from time import sleep, time
from threading import Thread, Lock
from queue import Queue, Empty
from whad.esb.esbaddr import ESBAddress
from sys import _getframe as getframe

import logging
logger = logging.getLogger(__name__)

class UnifyingApplicativeLayerState(LayerState):
    def __init__(self):
        super().__init__()
        self.role = UnifyingRole.DONGLE
        self.locale = "fr"
        self.wait_wakeup = False
        self.transmit_timeouts = False
        self.aes_counter = 0
        self.synchronized = False
        self.check_timeouts = False
        self.current_timeout = None
        self.last_timestamp = None
        self.last_sync = None

@alias('app')
@state(UnifyingApplicativeLayerState)
class UnifyingApplicativeLayer(Layer):

    def configure(self, options={}):
        self.__timeout_thread = None
        self.__crypto_manager = None
        self.callbacks = {}
        self.__packets_queue = Queue(10)

    def dongle_callback(func):
        def run_callback(*args, **kwargs):
            callbacks = getattr(args[0], "callbacks")
            execute = True
            if func.__name__ in callbacks and callable(callbacks[func.__name__]):
                execute = callbacks[func.__name__](*args[1:], **kwargs)
            if execute is None or execute:
                func(*args, **kwargs)
        return run_callback

    @property
    def aes_counter(self):
        return self.state.aes_counter

    @aes_counter.setter
    def aes_counter(self, counter):
        self.state.aes_counter = counter

    @property
    def locale(self):
        return self.state.locale

    @locale.setter
    def locale(self, value):
        self.state.locale = value

    def _check_timeouts_thread(self):
        while self.state.check_timeouts:
            if self.state.current_timeout is not None and self.state.last_timestamp is not None:
                if (int(time()*1000) - self.state.last_timestamp) > self.state.current_timeout * 10:
                    self.state.current_timeout = None
                    self.state.last_timestamp = None
                    self.on_desynchronized()
                else:
                    sleep(0.1)
            sleep(0.1)

    def _start_timeout_thread(self):
        self._stop_timeout_thread()
        self.state.transmit_timeouts = True
        self.__timeout_thread = Thread(target=self._transmit_timeouts_thread, daemon=True)
        self.__timeout_thread.start()

    def _stop_timeout_thread(self):
        if self.__timeout_thread is not None:
            self.state.transmit_timeouts = False
            self.__timeout_thread.join()
            self.__timeout_thread = None


    def _start_check_timeout_thread(self):
        self._stop_check_timeout_thread()
        self.state.check_timeouts = True
        self.__timeout_thread = Thread(target=self._check_timeouts_thread, daemon=True)
        self.__timeout_thread.start()

    def _stop_check_timeout_thread(self):
        if self.__timeout_thread is not None:
            self.state.check_timeouts = False
            self.__timeout_thread.join()
            self.__timeout_thread = None

    def _transmit_timeouts_thread(self):
        while self.state.transmit_timeouts or not self.__packets_queue.empty():
            try:
                self.send_message(Logitech_Set_Keepalive_Payload(timeout=1250))
                packet = self.__packets_queue.get(timeout=0.01, block=False)
                self.send_message(packet)
                self.send_message(Logitech_Keepalive_Payload(timeout=1250))
            except Empty as empty_err:
                try:
                    self.send_message(Logitech_Keepalive_Payload(timeout=1250))
                    sleep(0.01)
                except WhadDeviceTimeout:
                    return
                except WhadDeviceDisconnected:
                    return
            except WhadDeviceTimeout:
                return
            except WhadDeviceDisconnected:
                return

    def send_message(self, message, waiting_ack=False):
        result = self.send('ll', Logitech_Unifying_Hdr()/message, tag='data')
        return result

    def prepare_message(self, message):
        self.__packets_queue.put(message)
        return True

    def __del__(self):
        self.unlock_channel()

    @property
    def role(self):
        return self.state.role

    @role.setter
    def role(self, role):
        self.state.role = role
        if self.state.role == UnifyingRole.DONGLE:
            self.get_layer('ll').role = ESBRole.PRX
        else:
            self.get_layer('ll').role = ESBRole.PTX

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
        if self.state.role == UnifyingRole.DONGLE:
            self._start_check_timeout_thread()
        else:
            self._start_timeout_thread()

    def lock_channel(self):
        if self.__timeout_thread is None:
            logger.info('locking channel.')
            self.enable_timeouts()

    def unlock_channel(self):
        if self.__timeout_thread is not None:
            logger.info('unlocking channel.')
            self._stop_timeout_thread()

    def move_mouse(self, x, y):
        self.lock_channel()
        try:
            answer = self.prepare_message(
                Logitech_Mouse_Payload(
                    movement=LogitechUnifyingMouseMovementConverter.get_hid_data_from_coordinates(x, y)
                )
            )
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
                        ctrl=ctrl,
                        alt=alt,
                        shift=shift,
                        gui=gui,
                        locale=self.state.locale
                    )
                )
            )

            keep_alive = self.prepare_message(
                Logitech_Keepalive_Payload(timeout=1250)
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
            keep_alive = self.prepare_message(
                Logitech_Keepalive_Payload(timeout=1250)
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

        counter = self.state.aes_counter if force_counter is None else force_counter

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
                            locale=self.state.locale
                        ),
                        unknown=201,
                        aes_counter=counter
                    )
                )
            )
            keep_alive = self.prepare_message(
                Logitech_Keepalive_Payload(timeout=1250)
            )
            answer_release = self.prepare_message(
                self.__crypto_manager.encrypt(

                    Logitech_Encrypted_Keystroke_Payload(
                        hid_data=b"\x00"*7,
                        unknown=201,
                        aes_counter=counter+1
                    )
                )
            )

            if force_counter is None:
                self.aes_counter += 2

            return answer_press and answer_release
        except InvalidHIDData:
            return False

    #@dongle_callback
    @source('ll', 'synchronized')
    def on_synchronized(self, timestamp=None):
        if timestamp is None:
            timestamp = time()
        logger.info("Synchronized !")
        if self.state.role == UnifyingRole.DONGLE:
            self.enable_timeouts()
        self.state.synchronized = True

    #@dongle_callback
    @source('ll', 'desynchronized')
    def on_desynchronized(self, timestamp=None):
        #print("desync")
        if timestamp is None:
            timestamp = time()
        logger.info("Desynchronized.")
        self.state.synchronized = False

    def wait_synchronization(self):
        while not self.state.synchronized:
            sleep(0.01)
        return True

    def wait_wakeup(self):
        self.get_layer('ll').address = ESBAddress(self.get_layer('ll').address).base + ":00"
        self.state.wait_wakeup = True
        while self.state.wait_wakeup:
            sleep(0.01)
        return True

    #@dongle_callback
    @source('ll', 'data')
    def on_data(self, data):
        current_time = int(time() * 1000)
        self.state.last_timestamp = current_time

        if self.state.role == UnifyingRole.DONGLE:
            if not self.state.synchronized:
                self.on_synchronized()

            if self.state.wait_wakeup:
                if Logitech_Wake_Up_Payload in data:
                    # Weird checksum, force it
                    pkt = Logitech_Unifying_Hdr(dev_index = 0,checksum=0xAC)/Logitech_Waked_Up_Payload(wakeup_dev_index=data.dev_index)
                    self.send(pkt, tag='ack')
                elif hasattr(data,"dev_index"):
                    self.get_layer('ll').address = ESBAddress(self.get_layer('ll').address).base + ":{:02x}".format(data.dev_index)
                    self.state.wait_wakeup = False
                    self.on_wakeup(data.dev_index)

            if Logitech_Set_Keepalive_Payload in data:
                self.on_set_keepalive(data.timeout)

            if Logitech_Keepalive_Payload in data:
                self.on_keepalive(data.timeout)

            if Logitech_Mouse_Payload in data:
                self.on_mouse_payload(data)

            if Logitech_Multimedia_Key_Payload in data and data.hid_key_scan_code != b"\x00"*4:
                try:
                    self.on_multimedia_keystroke(MultimediaKey(data.hid_key_scan_code[0]))
                except ValueError:
                    pass
            if Logitech_Unencrypted_Keystroke_Payload in data:
                self.on_unencrypted_keystroke_payload(data)

            if Logitech_Encrypted_Keystroke_Payload in data:
                self.on_encrypted_keystroke_payload(data)

    @dongle_callback
    def on_multimedia_keystroke(self, key):
        logger.info("Multimedia keystroke (key="+str(key.name)+")")

    @dongle_callback
    def on_unencrypted_keystroke_payload(self, data):
        logger.info("Unencrypted Keystroke Payload (payload="+bytes(data).hex()+")")
        if data.hid_data != b"\x00"*7:
            try:
                key = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(data.hid_data, locale=self.state.locale)
                self.on_unencrypted_keystroke(key)
            except (InvalidHIDData, HIDCodeNotFound):
                pass

    @dongle_callback
    def on_encrypted_keystroke_payload(self, data):
        logger.info("Encrypted Keystroke Payload (payload="+bytes(data).hex()+")")
        if self.__crypto_manager is not None:
            try:
                decrypted = self.__crypto_manager.decrypt(data)
                logger.info("\t-> Decrypted payload: ", bytes(decrypted).hex())
                if decrypted.hid_data != b"\x00"*7:
                    key = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(decrypted.hid_data, locale=self.state.locale)
                    self.on_encrypted_keystroke(key)
            except (MissingEncryptedKeystrokePayload, InvalidHIDData, HIDCodeNotFound):
                pass

    @dongle_callback
    def on_encrypted_keystroke(self, key):
        logger.info("Encrypted keystroke (key="+str(key)+")")
        self.on_keystroke(key)

    @dongle_callback
    def on_unencrypted_keystroke(self, key):
        logger.info("Unencrypted keystroke (key="+str(key)+")")
        self.on_keystroke(key)

    @dongle_callback
    def on_keystroke(self, key):
        logger.info("Keystroke ("+str(key)+")")

    @dongle_callback
    def on_wakeup(self, dev_index):
        logger.info("Waked up by device (dev_index=0x{:02x})".format(dev_index))

    @dongle_callback
    def on_set_keepalive(self, timeout):
        logger.info("Set keep alive (timeout="+str(timeout)+")")
        self.state.current_timeout = timeout

    @dongle_callback
    def on_keepalive(self, timeout):
        logger.info("Keep alive (timeout="+str(timeout)+")")
        self.state.current_timeout = timeout

    @dongle_callback
    def on_mouse_payload(self, data):
        try:
            logger.info("Mouse payload (payload="+bytes(data).hex()+")")
            converter = LogitechUnifyingMouseMovementConverter()
            x, y = converter.get_coordinates_from_hid_data(data.movement)
            if x != 0 or y != 0:
                self.on_move_mouse(x, y)

            button = ClickType(data.button_mask)
            if button != ClickType.NONE:
                self.on_click_mouse(button)

            if data.wheel_x != 0 or data.wheel_y != 0:
                self.on_wheel_mouse(data.wheel_x, data.wheel_y)
        except ValueError:
            pass

    @dongle_callback
    def on_wheel_mouse(self, x, y):
        logger.info("Mouse wheel (x="+str(x)+", y="+str(y)+")")

    @dongle_callback
    def on_move_mouse(self, x, y):
        logger.info("Mouse move (x="+str(x)+", y="+str(y)+")")

    @dongle_callback
    def on_click_mouse(self, type):
        logger.info("Mouse click (click="+str(type.name)+")")

    @source('ll', 'ack')
    def on_acknowledgement(self, ack):
        pass

    def __del__(self):
        self.stop()

    def stop(self):
        if self.__timeout_thread is not None:
            if self.state.role == UnifyingRole.DONGLE:
                self._stop_check_timeout_thread()
            else:
                self._stop_timeout_thread()

'''
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
        self.__wait_wakeup = False
        self.__synchronized = False
        self.callbacks = {}
        self.__packets_queue = Queue(10)


    def dongle_callback(func):
        def run_callback(*args, **kwargs):
            callbacks = getattr(args[0], "callbacks")
            execute = True
            if func.__name__ in callbacks and callable(callbacks[func.__name__]):
                execute = callbacks[func.__name__](*args[1:], **kwargs)
            if execute is None or execute:
                func(*args, **kwargs)
        return run_callback

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
        self.__timeout_thread = Thread(target=self._transmit_timeouts_thread)
        self.__timeout_thread.start()

    def _stop_timeout_thread(self):
        if self.__timeout_thread is not None:
            self.__transmit_timeouts = False
            self.__timeout_thread.join()
            self.__timeout_thread = None

    def _transmit_timeouts_thread(self):
        while self.__transmit_timeouts or not self.__packets_queue.empty():
            self.send_message(Logitech_Set_Keepalive_Payload(timeout=1250))
            try:
                packet = self.__packets_queue.get(timeout=0.01, block=False)
                self.send_message(packet)
                self.send_message(Logitech_Keepalive_Payload(timeout=1250))
            except Empty:
                self.send_message(Logitech_Keepalive_Payload(timeout=1250))
                sleep(0.01)

    def send_message(self, message, waiting_ack=False):
        result = self.__llm.send_data(Logitech_Unifying_Hdr()/message)
        return result

    def prepare_message(self, message):
        self.__packets_queue.put(message)
        return True

    def __del__(self):
        self.unlock_channel()

    @property
    def role(self):
        return self.__role

    @role.setter
    def role(self, role):
        self.__role = role
        if self.__role == UnifyingRole.DONGLE:
            self.__llm.role = ESBRole.PRX
        else:
            self.__llm.role = ESBRole.PTX

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
            print("[i] locking channel.")
            self.enable_timeouts()

    def unlock_channel(self):
        if self.__timeout_thread is not None:
            print("[i] unlocking channel.")
            self._stop_timeout_thread()

    def move_mouse(self, x, y):
        self.lock_channel()
        try:
            answer = self.prepare_message(
                Logitech_Mouse_Payload(
                    movement=LogitechUnifyingMouseMovementConverter.get_hid_data_from_coordinates(x, y)
                )
            )
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
            keep_alive = self.prepare_message(
                Logitech_Keepalive_Payload(timeout=1250)
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
            keep_alive = self.prepare_message(
                Logitech_Keepalive_Payload(timeout=1250)
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
                    )
                )
            )
            keep_alive = self.prepare_message(
                Logitech_Keepalive_Payload(timeout=1250)
            )
            answer_release = self.prepare_message(
                self.__crypto_manager.encrypt(

                    Logitech_Encrypted_Keystroke_Payload(
                        hid_data=b"\x00"*7,
                        unknown=201,
                        aes_counter=counter+1
                    )
                )
            )

            if force_counter is None:
                self.aes_counter += 2

            return answer_press and answer_release
        except InvalidHIDData:
            return False

    @dongle_callback
    def on_synchronized(self):
        print("[i] Synchronized !")
        self.__synchronized = True

    @dongle_callback
    def on_desynchronized(self):
        print("[i] Desynchronized.")
        self.__synchronized = False

    def wait_synchronization(self):
        while not self.__synchronized:
            sleep(0.01)
        return True

    def wait_wakeup(self):
        self.__llm.address = ESBAddress(self.__llm.address).base + ":00"
        self.__wait_wakeup = True
        while not self.__wait_wakeup:
            sleep(0.01)
        return True

    @dongle_callback
    def on_data(self, data):
        if self.__role == UnifyingRole.DONGLE:
            if not self.__synchronized:
                self.on_synchronized()

            if self.__wait_wakeup:
                if Logitech_Wake_Up_Payload in data:
                    # Weird checksum, force it
                    pkt = Logitech_Unifying_Hdr(dev_index = 0,checksum=0xAC)/Logitech_Waked_Up_Payload(wakeup_dev_index=data.dev_index)
                    self.__llm.prepare_acknowledgment(
                        pkt
                    )
                elif hasattr(data,"dev_index"):
                    self.__llm.address = ESBAddress(self.__llm.address).base + ":{:02x}".format(data.dev_index)
                    self.__wait_wakeup = False
                    self.on_wakeup(data.dev_index)

            if Logitech_Set_Keepalive_Payload in data:
                self.on_set_keepalive(data.timeout)

            if Logitech_Keepalive_Payload in data:
                self.on_keepalive(data.timeout)

            if Logitech_Mouse_Payload in data:
                self.on_mouse_payload(data)

            if Logitech_Multimedia_Key_Payload in data and data.hid_key_scan_code != b"\x00"*4:
                try:
                    self.on_multimedia_keystroke(MultimediaKey(data.hid_key_scan_code[0]))
                except ValueError:
                    pass
            if Logitech_Unencrypted_Keystroke_Payload in data:
                self.on_unencrypted_keystroke_payload(data)

            if Logitech_Encrypted_Keystroke_Payload in data:
                self.on_encrypted_keystroke_payload(data)

    @dongle_callback
    def on_multimedia_keystroke(self, key):
        print("[i] Multimedia keystroke (key="+str(key.name)+")")

    @dongle_callback
    def on_unencrypted_keystroke_payload(self, data):
        print("[i] Unencrypted Keystroke Payload (payload="+bytes(data).hex()+")")
        if data.hid_data != b"\x00"*7:
            try:
                key = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(data.hid_data, locale=self.__locale)
                self.on_unencrypted_keystroke(key)
            except (InvalidHIDData, HIDCodeNotFound):
                pass

    @dongle_callback
    def on_encrypted_keystroke_payload(self, data):
        print("[i] Encrypted Keystroke Payload (payload="+bytes(data).hex()+")")
        if self.__crypto_manager is not None:
            try:
                decrypted = self.__crypto_manager.decrypt(data)
                print("\t-> Decrypted payload: ", bytes(decrypted).hex())
                if decrypted.hid_data != b"\x00"*7:
                    key = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(decrypted.hid_data, locale=self.__locale)
                    self.on_encrypted_keystroke(key)
            except (MissingEncryptedKeystrokePayload, InvalidHIDData, HIDCodeNotFound):
                pass

    @dongle_callback
    def on_encrypted_keystroke(self, key):
        print("[i] Encrypted keystroke (key="+str(key)+")")
        self.on_keystroke(key)

    @dongle_callback
    def on_unencrypted_keystroke(self, key):
        print("[i] Unencrypted keystroke (key="+str(key)+")")
        self.on_keystroke(key)

    @dongle_callback
    def on_keystroke(self, key):
        print("[i] Keystroke ("+str(key)+")")

    @dongle_callback
    def on_wakeup(self, dev_index):
        print("[i] Waked up by device (dev_index=0x{:02x})".format(dev_index))

    @dongle_callback
    def on_set_keepalive(self, timeout):
        print("[i] Set keep alive (timeout="+str(timeout)+")")

    @dongle_callback
    def on_keepalive(self, timeout):
        print("[i] Keep alive (timeout="+str(timeout)+")")

    @dongle_callback
    def on_mouse_payload(self, data):
        print("[i] Mouse payload (payload="+bytes(data).hex()+")")
        converter = LogitechUnifyingMouseMovementConverter()
        x, y = converter.get_coordinates_from_hid_data(data.movement)
        if x != 0 or y != 0:
            self.on_move_mouse(x, y)

        button = ClickType(data.button_mask)
        if button != ClickType.NONE:
            self.on_click_mouse(button)

        if data.wheel_x != 0 or data.wheel_y != 0:
            self.on_wheel_mouse(data.wheel_x, data.wheel_y)

    @dongle_callback
    def on_wheel_mouse(self, x, y):
        print("[i] Mouse wheel (x="+str(x)+", y="+str(y)+")")

    @dongle_callback
    def on_move_mouse(self, x, y):
        print("[i] Mouse move (x="+str(x)+", y="+str(y)+")")

    @dongle_callback
    def on_click_mouse(self, type):
        print("[i] Mouse click (click="+str(type.name)+")")

    def on_acknowledgement(self, ack):
        pass
'''
