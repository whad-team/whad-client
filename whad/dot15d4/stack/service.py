from whad.dot15d4.exceptions import Dot15d4TimeoutException
from functools import wraps
from time import time
from queue import Queue, Empty
from inspect import signature
import logging

class Dot15d4Service:

    def __init__(self, manager, name=None, timeout_exception_class=Dot15d4TimeoutException):
        self._logger = logging.getLogger(self.__module__)
        self._manager = manager
        self._name = name if name is not None else self.__class__.__name__
        self._timeout_exception_class = timeout_exception_class
        self._queue = Queue()


    @property
    def manager(self):
        """
        Returns the associated manager.
        """
        return self._manager

    @property
    def database(self):
        """
        Alias to facilitate the manipulation of manager database.
        """
        return self._manager.database

    def add_packet_to_queue(self, packet):
        """
        Add an incoming packet to the queue.
        """
        self._queue.put(packet, block=True, timeout=None)

    def wait_for_packet(self, packet_filter, timeout=1.0):
        """Wait for a specific message type or error, other messages are dropped

        :param type packet_filter: Filtering lambda
        :param float timeout: Timeout value (default: 1 second)
        """
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self._queue.get(block=False,timeout=0.1)
                if packet_filter(msg):
                    return msg
            except Empty:
                pass
        raise self._timeout_exception_class()


    # Services primitives decorator
    def request(request_name):
        def _request(func):
            @wraps(func)
            def request_decorator(*args, **kwargs):
                self = args[0]
                self._logger.info("[{}] {} request ({},{})".format(args[0]._name, request_name, str(args[1:]),str(kwargs)))
                result = func(*args, **kwargs)
                self._logger.info("[{}] {} confirm ({})".format(args[0]._name, request_name, str(result)))
                return result
            return request_decorator
        return _request


    def response(response_name):
        def _response(func):
            @wraps(func)
            def response_decorator(*args, **kwargs):
                self = args[0]
                self._logger.info("[{}] {} response ({},{})".format(args[0]._name, request_name, str(args[1:]),str(kwargs)))
                result = func(*args, **kwargs)
                return result
            return response_decorator
        return _response


    def indication(indication_name):
        def _indication(func):
            @wraps(func)
            def indication_decorator(*args, **kwargs):
                self = args[0]
                pdu, parameters = func(*args, **kwargs)

                upper = self._manager.upper_layer.alias
                callback_kwargs = {"tag":indication_name}
                callback_kwargs.update(parameters)

                self._logger.info("[{}] {} indication ({},{})".format(self._name, indication_name, str(pdu), str(callback_kwargs)))
                return_value = self._manager.send(upper, pdu, **callback_kwargs)
                return return_value

            return indication_decorator
        return _indication
