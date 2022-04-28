.. _ntf-notifications:

GDK Notifications
=================

This section describes the notifications emitted by the library.

All notifications contain an ``"event"`` element which describes the type
of event being notified. The notification data is available under an element
named with the content of the ``"event"`` element.


.. _ntf-network:

Network notification
--------------------

Notified when the state of a session's underlying network connection changes.

.. code-block:: json

  {
    "event": "network",
    "network": {
      "wait_ms": 1000,
      "current_state": "disconnected",
      "next_state": "connected"
    }
  }

:current_state: One of ``"connected"`` or ``"disconnected"``. The current
    state of the network connection.
:next_state: One of ``"connected"`` or ``"disconnected"``. The
    next state that the connection will move to. If this value is the same as
    ``"current_state"`` then no state change is currently in progress.
:wait_ms: The number of milliseconds before the current state will change
   to the next state. ``0`` if the change will happen immediately or no change
   is due to occur.



.. _ntf-tor:

Tor notification
----------------

Notified when using the built-in Tor connection during connection establishment.

.. code-block:: json

  {
    "event": "tor",
    "tor": {
      "progress": 20,
      "summary": "Establishing an encrypted directory connection",
      "tag": "onehop_create"
    }
  }

:tor/progress: An integer from 0-100 indicating the progress percentage.
:tor/summary: A human-readable summary of the current progress step.
:tor/onehop_create: A fixed identifier string for the current progress step.



Settings notification
---------------------

Notified upon successful authentication. Describes the current wallet settings.

.. code-block:: json

   {
      "event": "settings",
      "settings": {}
   }

:settings: Contains the :ref:`settings` of the user.


.. _ntf-twofactor-reset:

Two factor reset notification
-----------------------------

Notified by multisig sessions upon successful authentication. Describes the
current two factor reset status of the wallet.

.. code-block:: json

   {
      "event": "twofactor_reset",
      "twofactor_reset": {}
   }

:twofactor_reset: Contains the ``"twofactor_reset"`` portion of :ref:`twofactor_configuration`.


.. _ntf-block:

Block notification
------------------

Notified when a new block is mined by the network.

.. code-block:: json

  {
     "event": "block",
     "block": {
       "block_hash": "00000000a09b62cc7c076cf8bb25840e67bb5f9f47492f8a82a09105a6aab72d",
       "block_height": 2138311,
       "initial_timestamp": 1489943482,
       "previous_hash": "00000000000000bcf344da3c3d691f5581136bf78c52de4c712949541f0ccf3c"
     }
  }

:block/block_hash: The hash of the block.
:block/block_height: The height of the block.
:block/initial_timestamp: Multisig only. The time that the users wallet was created, in seconds since the epoc.
:block/previous_hash: The hash of the block prior to this block.


.. _ntf-transaction:

Transaction notification
------------------------

Notified when a new transaction is received by the wallet.

.. code-block:: json

  {
    "event":"transaction",
    "transaction":{
        "satoshi":50000,
        "subaccounts":[
            0
        ],
        "txhash":"2bee55e07ab6cc520487f57cb74e87c2960d5f01d291d34f6b395417a276a42c",
        "type":"incoming"
    }
  }

:transaction/satoshi: Bitcoin only. The net amount of the transaction (always positive).
:transaction/subaccounts: The wallet subaccounts the transaction affects.
:transaction/txhash: The txid of the transaction.
:transaction/type: Bitcoin only. One of ``"incoming"``, ``"outgoing"`` or ``"redeposit"``.


.. _ntf-ticker:

Ticker notification
-------------------

Notified when the user's exchange rate changes.

.. code-block:: json

  {
    "event": "ticker",
    "ticker": {
      "currency": "NZD",
      "exchange": "KIWICOIN",
      "rate": "44100.84"
    }
  }

:ticker/currency: The user's chosen fiat currency.
:ticker/exhange: The user's chosen exchange source.
:ticker/rate: The price of 1 Bitcoin expressed in the user's fiat currency, expressed as a floating point string.
