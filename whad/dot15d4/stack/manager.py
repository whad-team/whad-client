class Dot15d4Manager:
    """
    Defines a 802.15.4 manager, containing some services.
    """
    def __init__(self, services={}):
        self._services = services

    def get_service(self, service):
        if service in self._services:
            return self._services[service]
        return None

    @property
    def services(self):
        return self._services
