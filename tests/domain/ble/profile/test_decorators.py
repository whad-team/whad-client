import pytest
from whad.ble.profile import CharacteristicHook, Characteristic, UUID, PrimaryService, \
    read, write, subscribed, unsubscribed, written

@pytest.fixture
def service():
    return PrimaryService(UUID(0x1800))

@pytest.fixture
def characteristic(service):
    charac = Characteristic(uuid=UUID(0x2A00))
    charac.attach(service)
    return charac

def test_characteristic_hook_decorator(characteristic):
    """Test CharacteristicHook instanciation
    """

    @CharacteristicHook(characteristic)
    def on_something():
        pass

    assert(on_something.characteristic == "1800:2A00")
    assert(isinstance(on_something.hooks, list))
    assert(len(on_something.hooks) == 0)

def test_read_decorator(characteristic) :
    """Test read() decorator
    """
    print("charac: %s" % characteristic)
    @read(characteristic)
    def on_something():
        pass

    assert("read" in on_something.hooks)

def test_write_decorator(characteristic) :
    """Test write() decorator
    """

    @write(characteristic)
    def on_something():
        pass

    assert("write" in on_something.hooks)

def test_written_decorator(characteristic) :
    """Test written() decorator
    """

    @written(characteristic)
    def on_something():
        pass

    assert("written" in on_something.hooks)

def test_subscribed_decorator(characteristic) :
    """Test subscribed() decorator
    """

    @subscribed(characteristic)
    def on_something():
        pass

    assert("sub" in on_something.hooks)

def test_unsubscribed_decorator(characteristic) :
    """Test unsubscribed() decorator
    """

    @unsubscribed(characteristic)
    def on_something():
        pass

    assert("unsub" in on_something.hooks)
