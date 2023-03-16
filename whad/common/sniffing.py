'''
This is the base class representing a event occuring during sniffing.
'''

class EventsManager:
    def __init__(self):
        self.__listeners = []

    def add_event_listener(self, listener):
        self.__listeners.append(listener)

    def trigger_event(self, event):
        for listener in self.__listeners:
            listener(event)

class SniffingEvent:
    def __init__(self, name):
        self.name = name

    @property
    def message(self):
        return None
