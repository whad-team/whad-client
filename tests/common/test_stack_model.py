"""Unit tests for WHAD's stack model."""

import pytest
from typing import Optional

from whad.common.stack import Layer, LayerState, alias, source, state
from whad.common.stack.layer import DEFAULT_FLAVOR

@alias("bar")
@state(LayerState)
class DummySublayer(Layer):
    """Dummy sublayer with alias 'bar'."""

    @source("foo")
    def recv_from_foo(self, data: str):
        """Process data sent by foo."""
        if data == "ping":
            print("[bar] Received 'ping' from foo, send 'pong'")
            self.send("foo", "pong")
        else:
            print("[bar] received %s from foo" % data)

    @source("foo", tag="abc")
    def recv_from_foo_with_abc_tag(self, data: str):
        """Received a tagged message from foo."""
        self.send("foo", "ack")

class DummySublayerVariant(DummySublayer):
    """A variant of DummySubLayer."""

    @source("foo")
    def recv_from_foo(self, data: str):
        """Process data sent by foo."""
        self.send("foo", "yolo")

    @source("foo", tag="abc")
    def recv_from_foo_with_abc_tag(self, data: str):
        """Received a tagged message from foo."""
        self.send("foo", "ackack")

@alias("foo")
class DummyStack(Layer):
    """Dummy stack, PHY layer."""

    def __init__(self, parent, layer_name, options={}, flavor=DEFAULT_FLAVOR):
        """Initialize our dummy stack."""
        super().__init__(parent, layer_name, options, flavor=flavor)
        self.recv = None

    def send_to_bar(self, data: str, tag: str = 'default'):
        """Send a message to bar."""
        self.send("bar", data, tag=tag)

    @source("bar")
    def recv_from_bar(self, data):
        """Receive a message from bar."""
        print("[foo] received %s from bar" % data)
        self.recv = data

DummyStack.add(DummySublayer)
DummyStack.add(DummySublayerVariant, flavor="yolo")

@pytest.fixture
def dummy_stack():
    return DummyStack

@pytest.fixture
def dummy_stack_instance(dummy_stack):
    return dummy_stack(None, "foo")

@pytest.fixture
def yolo_stack_instance(dummy_stack):
    return dummy_stack(None, "foo", flavor="yolo")

def test_stack_instance(dummy_stack):
    """Instantiate stack and check all layers are correctly created."""
    stack = dummy_stack(None, "foo")
    assert isinstance(stack, DummyStack)
    assert stack.get_layer("bar") is not None
    assert isinstance(stack.get_layer("bar"), DummySublayer)

def test_stack_messaging(dummy_stack_instance):
    """Send message to stack's sublayer and wait for an answer sent back
    by the sublayer."""
    dummy_stack_instance.send_to_bar("ping")
    assert dummy_stack_instance.recv == "pong"

def test_stack_message_tag(dummy_stack_instance):
    """Send message to stack's sublayer and wait for an answer sent back
    by the sublayer."""
    dummy_stack_instance.send_to_bar("ping", tag="abc")
    assert dummy_stack_instance.recv == "ack"

def test_stack_message_bad_tag(dummy_stack_instance):
    """Send a message to an undefined tag, it must be caught
    by the default handler based on message source."""
    dummy_stack_instance.recv = ""
    dummy_stack_instance.send_to_bar("ping", tag="xxx")
    assert dummy_stack_instance.recv == "pong"

def test_stack_flavor_message_tag(yolo_stack_instance):
    """Send message to stack's sublayer and wait for an answer sent back
    by the sublayer."""
    yolo_stack_instance.send_to_bar("ping", tag="abc")
    assert yolo_stack_instance.recv == "ackack"

def test_stack_flavor_messaging(yolo_stack_instance):
    """Send message to stack's sublayer and wait for an answer sent back
    by the sublayer."""
    yolo_stack_instance.send_to_bar("ping")
    assert yolo_stack_instance.recv == "yolo"

def test_stack_flavor_instance(dummy_stack):
    """Instantiate stack with a specific flavor and check all layers are
    correctly created."""
    stack = dummy_stack(None, "foo", flavor="yolo")
    assert isinstance(stack, DummyStack)
    assert stack.get_layer("bar") is not None
    assert isinstance(stack.get_layer("bar"), DummySublayerVariant)

