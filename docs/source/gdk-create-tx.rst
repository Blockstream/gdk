.. _create-tx-details:

GDK Create Transaction JSON
===========================

This section details how to create various kinds of transaction using
`GA_create_transaction`. Once created, the resulting JSON is generally passed
to `GA_blind_transaction` (on Liquid) to blind its outputs. Following this it
is passed to `GA_sign_transaction` to obtain signatures, then broadcast to the
network via `GA_send_transaction` or `GA_broadcast_transaction`.

Overview
--------

The caller passes details about the transaction they would like to construct.
The returned JSON contains the resulting transaction and an ``"error"`` element
which is either empty if the call succeeded in creating a valid transaction or
contains an error code describing the problem.

Building transactions can be done iteratively, by passing the result of one
call into the next after making changes to the returned JSON. This is useful for
interactive transaction creation as it allows users to see the effect of
changes such as different fee rates interactively, and to fix errors on the fly.
Because gdk will create new change addresses when constructing transactions,
passing the result of the last call to `GA_create_transaction` makes each call
significantly faster and more efficient compared to passing in the initial JSON.

When using gdk as a integration solution, `GA_create_transaction` is generally
only called once, and if an error occurs the operation is aborted.

Note that the returned JSON will contain additional elements beyond those
documented here. The caller should not attempt to change these elements; the
documented inputs are the only user-level changes that should be made, and
the internal elements may change name or meaning from release to release.

Mandatory and Optional Elements
-------------------------------

Only two elements are always mandatory: ``"addressees"`` and ``"utxos"``. A
transaction sending some amount from the wallet can be created using e.g:

.. code-block:: json

  {
    "addressees": [ {} ],
    "utxos": { }
  }


:addressees: Mandatory. An array of :ref:`addressee` elements, one for each recipient.
:utxos: Mandatory. The UTXOs to fund the transaction with, :ref:`unspent-outputs` as
        returned by `GA_get_unspent_outputs`. Any UTXOs present are candidates for
        inclusion in the transaction.

Optional elements allow more precise control over the transaction:

:fee_rate: Defaults to the sessions default fee rate setting. The fee rate in
           satoshi per 1000 bytes to use for fee calculation.
:utxo_strategy: Defaults to ``"default"``. Set to ``"manual"`` for manual UTXO
                selection.
:randomize_inputs: Defaults to ``true``. If set to ``true``, the
                   order of the used UTXOs in the created transaction is randomized.
:is_partial: Defaults to ``false``. Used for creating partial/incomplete
             transactions such as half-swaps. If set to ``true``, no change
             outputs will be created, fees will not be calculated or deducted
             from inputs, and the transaction inputs and outputs will not be expected
             to balance. Sets ``"randomize_inputs"`` to ``false``.
             Consider using `GA_create_swap_transaction` instead of this element.
:transaction_version: Defaults to ``2``. The Bitcoin/Liquid transaction version to use.
:transaction_locktime: Defaults to The current block with occasional random variance
                       for privacy. The transaction level locktime to use.

If you wish to customize a transaction further, consider creating a PSBT/PSET
directly from the wallets inputs and using `GA_psbt_sign` to sign it.


Returned metadata
-----------------

Some data returned when creating a transaction may be read by the user:

:error: If not empty, the error description that prevented the transaction being
        created.
:transaction: The hex-encoded resulting transaction. This may be partially
              complete or contain dummy data, e.g. missing blinding data or
              signatures before it is fully completed and signed. The vsize
              and weight elements described below are adjusted with reasonable
              estimates for any missing data until the transaction is fully signed.
:transaction_vsize: The expected final vsize of the ``"transaction"`` in vbytes.
:transaction_weight: The expected final weight of ``"transaction"`` in segwit weight units.
:calculated_fee_rate: The expected fee rate for the final signed transaction. This
                      may differ slightly from the requested ``"fee_rate"`` due
                      to variance in the size of witness data such as signatures.
:transaction_inputs: An array of the ``"utxos"`` elements that are used by the transaction.
:transaction_outputs: The transaction output details for the outputs of the transaction.


.. _addressee:

Addressee JSON
--------------

Describes an intended recipient for a transaction.

.. code-block:: json

  {
    "address": "2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b",
    "satoshi": 100000,
    "asset_id": "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
    "is_greedy": false
  }

:address: Mandatory. The address to send to. All address types for the network are supported.
          Additionally, `BIP 21 <https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki>`_
          URLs are supported along with the `Liquid adaptation <https://github.com/ElementsProject/elements/issues/805>`_.
          Note that BIP 70 payment requests are not supported.
:satoshi: Normally mandatory. The amount to send to the recipient in satoshi. May
          be omitted when ``"is_greedy"`` is ``true``.
:asset_id: Mandatory for Liquid, must not be present for Bitcoin. The asset to be
           sent to the recipient, in display hex format.
:is_greedy: Optional. If set to ``true``, this addressee will consume any
            remaining value from UTXOs that match its ``"asset_id"`` (or all
            UTXOs in the case of Bitcoin). Only one greedy output per asset
            is allowed. When set to ``true``, the value of the ``"satoshi"``
            element is ignored and will be overwritten with the computed value.

.. note:: When an addressee represents a wallet address, the entire contents
          of the `GA_get_receive_address` call made to fetch the address must
          be passed. If only the address is provided, the addressee will be
          treated as an external addressee, and e.g. the summary values of
          the transaction in the top-level "satoshi" element will not be
          correct.


Coin selection
--------------

Callers can control the UTXOs used when creating a transaction. When using
``"utxo_strategy"``: ``"default"``, Bitcoin and Liquid-Bitcoin UXTOs are
selected from the ``"utxos"`` element. The caller can reorder and filter
these UTXOs using the query parameters to `GA_get_unspent_outputs` to
control which UTXOs are used (and their ordering, if ``"randomize_inputs"``
is set to ``false``). For asset UTXOs under Liquid, the default strategy
attempts to select the minimum number of UTXOs to use without regard for
their ordering in the ``"utxos"`` element.

For finer control, setting ``"utxo_strategy"`` to ``"manual"`` allows the
UTXOs to be used to be placed directly into the ``"transaction_inputs"``
element by the caller. In this case, ``"utxos"`` is unused, and all given
UTXOs will be added to the resulting transaction.

The sum of input UTXOs for a given asset must be sufficient to cover the
amounts sent to any addressees receiving it, or an error will occur unless
``"is_partial"`` is ``true``. Excess amounts will be either be returned to
the wallet as change, or if an addressee has ``"is_greedy"`` set to ``true``
then the remainder will be assigned to it. When ``"utxo_strategy"`` is set
to ``"default"``, UTXOs from the ``"utxos"`` element will be omitted from
the created transaction if they are not needed.

Finally, creating a PSBT/PSET and using `GA_psbt_sign` to sign it allows
exact specification of all transaction details including UTXOs.


Re-deposit
----------

A re-deposit is just a standard sending transaction with the addressee being
an address from the users wallet as returned from `GA_get_receive_address`,
and ``is_greedy"`` in the addressee being set to ``"true"`` to consume all of
the UTXOs to redeposit.


Fee bump
--------

A fee bump or RBF transaction increases the fee rate of an outgoing transaction
that the caller has already submitted to the mempool, but which is not yet
confirmed.

To create a fee bump, the caller should include the transaction to bump in the
``"previous_transaction"`` element. This must be in the format returned
by `GA_get_transactions`. Additionally the new fee rate to bump to must be
given in ``"fee_rate"``, and any additional UTXOs to be used for providing the
funds for the fee increase given in ``"utxos"``.

.. code-block:: json

  {
    "previous_transaction": {},
    "fee_rate": 5000,
    "utxos": { }
  }

:previous_transaction: The transaction to bump, as returned from :ref:`tx-list`.
:fee_rate: The new fee rate in satoshi per 1000 bytes to use for fee
           calculation. This must be higher than the exiting fee rate
           in ``"previous_transaction"``.

Sweeping
--------

A sweep transaction moves coins from an address with a known private key to
another address. Unlike a simple send transaction, the coins to be moved are
not associated with the users wallet in any way. Sweeping is typically used
to move coins from a paper wallet into the users wallet.

To create a sweep transaction, use `GA_get_unspent_outputs_for_private_key`
to fetch the unspent outputs to sweep. Including these in the ``"utxos"``
element when creating a transaction will automatically handle signing them.

Note that you should generally set ``"is_greedy"`` for one of the transaction
addressees when sweeping to ensure that all of the UTXOs are spent together.

It is also possible to send the swept coin to an address that does not belong
to the callers wallet. Currently it is not possible to include sweep inputs
along with wallet inputs to combine spending.
