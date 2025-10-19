Advertiser role
===============

Bluetooth Low Energy advertising only feature is provided by a dedicated connector implementing the
*Broadcaster* role as defined in the Bluetooth specification, :class:`whad.ble.connector.Advertiser`.
This class drives a BLE-enable WHAD device to send advertisements with no stack bound.

Creating a Bluetooth Low Energy *advertiser*
--------------------------------------------

The :class:`~whad.ble.connector.Advertiser` class implements the Bluetooth Low Energy *Broadcaster*
role that is used to only *broadcast* advertisements without accepting any connection. This role
allows to send specific advertisements with specific type, on one or more advertising channels at
a given pace. These parameters can be specified in this class constructor and updated later.

Advertising parameters
~~~~~~~~~~~~~~~~~~~~~~

Advertisements can be of different types, each defining a specific behavior and giving any device
that receives them information about the advertised device. They are also used in the *Bluetooth Mesh*
protocol to convey data as a primary transport channel.

The first parameter ``adv_type`` required when creating an advertisement is the *advertisement type*. This parameter
defines the purpose of the advertisement and can be one of the values defined in the :class:`~whad.hub.ble.AdvType`
class:

- ``ADV_IND``: connectable and scannable undirected advertising
- ``ADV_DIRECT_IND``: connectable directed advertising
- ``ADV_SCAN_IND``: scannable undirected advertising
- ``ADV_NONCONN_IND``: non connectable undirected advertising

.. important::

    Other values from :class:`~whad.hub.ble.AdvType` will cause the advertiser to use connectable and
    scannable undirected advertisements.

Configuring the advertising channels used by the advertiser is possible through the ``channels`` parameter.
This parameter accepts a list of channels amongst the ones used for primary advertising: ``37``, ``38`` and ``39``.
At least one channel must be specified, and any channel that does not belong to these advertising channels
will be ignored.

Advertising interval can be specified through the ``interval`` parameter, a tuple of two integers specifying
the minimum and maximum values of the advertising interval to use (e.g. ``(<min value>, <max value>)``, with the following constraints:

- the minimum interval value must be greater than 0x20 and lower than the maximum interval value
- the maximum interval value must not exceed 0x4000 and be greater than minimum value

:class:`~whad.ble.connector.Advertiser` will raise a :class:`ValueError` exception whenever an invalid
parameter is passed to its constructor.

Here is a valid example of the creation of an advertiser sending non-connectable undirected
advertisements on channel 37 only, with an advertising interval comprised between 0x20 and 0x4000:

.. code-block:: python

    from whad.device import Device
    from whad.ble import Advertiser, AdvType
    from whad.ble.profile import AdvDataFieldList, AdvDataFlagsField

    adv = Advertiser(
        Device.create("hci0"),
        adv_data = AdvDataFieldList(AdvDataFlagsField()),
        scan_data = None,
        adv_type = AdvType.ADV_NONCONN_IND,
        channels = [37],
        interval = (0x20, 0x4000)
    )
    adv.start()

    # Wait for user input
    input("Press enter to stop advertising.")

If the advertising interval must be updated, the connector must be stopped before and restarted once the
parameters updated:

.. code-block:: python

    adv.stop()
    adv.interval = (0x1000, 0x2000)
    adv.start()


Advertising data
~~~~~~~~~~~~~~~~

Advertising data is specified through the ``adv_data`` parameter of the constructor, and scan response data
through the ``scan_data`` parameter. Both parameters accept either instances of :class:`~whad.ble.profile.AdvDataFieldList`
or directly a ``bytes`` object. In the first case, the advertiser will convert the provided advertising records
into a byte sequence while in the other it will directly use the provided byte sequence without checking its
completeness.


.. code-block:: python

    adv.adv_data = AdvDataFieldList(AdvDataFlagsField(), AdvDataCompleteLocalName(b"Foobar"))

.. note::

    Advertising and scan response data can be updated at any time, no matter the advertiser status.

Bluetooth Low Energy Advertiser connector
-----------------------------------------

.. autoclass:: whad.ble.connector.Advertiser
    :members:

