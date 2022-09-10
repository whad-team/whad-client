from whad.zigbee.exceptions import Dot15d4TimeoutException
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
                parameters = func(*args, **kwargs)
                callback_name = "on_{}".format(indication_name.lower().replace("-","_"))
                if (self._manager.upper_layer is not None and
                    hasattr(self._manager.upper_layer,callback_name) and
                    callable(getattr(self._manager.upper_layer,callback_name))
                ):
                    callback = getattr(self._manager.upper_layer, callback_name)
                    callback_args = []
                    callback_kwargs = {}
                    mismatch = False
                    for parameter_name, parameter in signature(callback).parameters.items():
                        if parameter_name in parameters:
                            if parameter.default is parameter.empty:
                                callback_args.append(parameters[parameter_name])
                            else:
                                callback_kwargs.update({parameter_name:parameters[parameter_name]})
                        else:
                            mismatch = True
                    self._logger.info("[{}] {} indication ({},{})".format(self._name, indication_name, str(callback_args), str(callback_kwargs)))
                    if mismatch:
                        self._logger.warning("[{}] {} indication parameters doesn't match with upper layer callback !".format(self._name, indication_name))
                        return_value = None
                    else:
                        return_value = callback(*callback_args, **callback_kwargs)
                else:
                    return_value = None
                return return_value
            return indication_decorator
        return _indication
