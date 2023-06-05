# Changelog

## Release 0.0.65

### Added

### Changed

### Fixed

### Removed

## Release 0.0.64 - 23-06-05

### Added
- GA_get_unspent_outputs: Singlesig: Liquid: set `is_confidential`.

### Changed
- Singlesig: switch from polling to subscription for transactions data. This
  change is transparent for the caller, but it should improve performances and
  reduce the server load.


## Release 0.0.63 - 23-05-31

### Added
- Liquid: Transaction blinding is now performed using a new call
  GA_blind_transaction, which should be called after creating and before
  signing the tx.
- Liquid: Hardware wallet capability JSON now contains a new field
  "supports_external_blinding". This should be set to true when registering
  a signer that can blind/sign transactions with blinded outputs from
  wallets other than the callers wallet (for example, a 2 step swap).

### Changed
- FFI (validate_call): Input JSON parameters are now moved internally and will be
  empty when an API call returns. This only affects C and C++ callers.
- GA_validate: When validating addressees, the entered amount is also validated
  and converted into satoshis. Additionally, the scriptpubkey and blinding public
  key are extracted from the address and returned where applicable.
- GA_sign_transaction/GA_send_transaction: The "script" element of the returned
  "transaction_outputs" elements has been renamed to "scriptpubkey" to reflect
  its contents more accurately.
- Liquid/JSON: The keys `blinded` and `confidential` in returned JSON have been
  renamed for consistency and to avoid confusion. `is_blinded` now always refers
  to a transaction input or output which has been blinded, i.e. its value and
  asset have been replaced with blinded commitments. `is_blinded` at the
  top-level of transaction JSON indicates that the transaction has been fully
  blinded and is ready for signing. `is_confidential` now always refers to
  an address or addressee element having a confidential address.
- Liquid: update hard-coded asset icons.

### Fixed

### Removed

## Release 0.0.62 - 2023-04-23

### Added

### Changed

### Fixed
- Watch Only: Fix old-style watch-only sessions fetching UTXOs and balances.

### Removed
- GA_create_transaction (and sign/send): The `has_change` element has been removed.
- GA_create_transaction (and blind/sign/send): The `transaction_size` element
  has been removed. It can instead be computed from the `transaction` element.
- GA_sign_transaction (and blind/send): The `utxos` element is now removed when the
  handler returns, as it is only used for transaction creation.
- GA_create_transaction(Liquid/AMP): For transactions involving AMP subaccounts,
  the required blinding nonces for outputs are no longer available in the
  individual "transaction_outputs" elements. Instead they should be fetched from
  "blinding_nonces" in the top-level transaction details if required.

## Release 0.0.61 - 2023-04-18

### Fixed
- Allow GA_decrypt_with_pin to decrypt pin_data created with GA_set_pin.

## Release 0.0.60 - 2023-04-18

### Fixed
- Fix artifacts for OSX builds.

## Release 0.0.59 - 2023-04-12

### Added

- GA_login_user: add support for Electrum watch only. It is now possible to
  login with a list of xpubs or descriptors.
- GA_psbt_sign: add support for Liquid Electrum sessions.

### Changed
- GA_get_twofactor_config: Fiat pricing limits no longer return corresponding
  converted BTC amounts. When "is_fiat" is `true`, the caller should convert
  the amount themselves using GA_convert_amount if desired.
- FFI (All calls): Input JSON parameters are now moved internally and will be
  empty when an API call returns. This only affects C and C++ callers.
- Singlesig: GA_create_transaction now has aligned behavior with multisig:
  previous workarounds to handle the differences between the session types
  can be removed.
- Liquid: Singlesig: Allow 32 bytes master blinding keys, consistently with
  multisig.
- Build: Replace meson with cmake and make sqlite3 an external dependencies,
  check the updated README for the new build instructions.

### Fixed
- GA_sign_transaction/GA_send_transaction: Fixed exception thrown when a fiat
  spending limit is set but cannot be used (for example, because the pricing
  source is unavailable). When this occurs, 2FA will be required.
- GA_get_twofactor_config: Fixed exception thrown when a fiat pricing source
  is unavailable and a fiat spending limit is set.
- Singlesig: Fix handling of some invalid proxies.
- Fix a bug in Android build.
- Fix missing URL overrides in network parameters.

### Removed
- Removed Python wheel for Ubuntu 18.04, replaced with wheel for Ubuntu 20.04

## Release 0.0.58 - 2023-02-06

### Added
- GA_validate: Add support for validating transaction addressees.
- GA_get_unspent_outputs: add a `sort_by` element to return sorted results.
- Added new function GA_sign_message

### Changed
- GA_create_transaction: Sweeping and re-deposit transactions now require the
  caller to provide the recipient address. GA_get_receive_address can be used
  for this purpose.
- GA_create_transaction: If addressees are not provided, some fields of the
  result transaction may not be populated.
- GA_create_transaction: The `addressees_have_assets` element has been removed.
- GA_get_unspent_outputs: The default sorting for multisig non-2of2
  subaccounts has been changed from oldest-first to largest-first.
- Singlesig: GA_change_settings, GA_get_available_currencies and
  GA_convert_amount have now aligned behavior with multisig: all the prices
  and venues are matched and changing settings actually influence the fiat
  currency returned from GA_convert_amount.
- GA_encrypt_with_pin: Add `hmac` field.
- Liquid: update hard-coded asset icons.

### Fixed
- Liquid: Fix the min fee and dust threshold for multi/singlesig respectively.
- Liquid: Respect the dust limit for non-fee L-BTC outputs.
- GA_create_transaction: `id_no_amount_specified` is now returned under all
  circumstances where an amount is not given in an addressee.
- GA_create_transaction: Non-partial transactions where `utxo_strategy` is set
  to `"manual"` now return an error if an asset is provided in `used_utxos`
  that does not correspond to an addressee.
- Singlesig: GA_get_transactions: fix script serialization
- Singlesig: fixes for block and transaction notifications

### Removed

## Release 0.0.57 - 2022-11-23

### Added
- GA_get_subaccount: add user_path, core_descriptor, slip132_extended_pubkey.
- GA_get_assets: add ability to fetch information about Liquid assets by
specifying one or more of the following fields: `names`, `tickers`, `category`.

### Changed

- Singlesig: GA_convert_amount: If a fallback fiat rate is provided the
  function will return that rate immediately instead of waiting for the latest
  rate to be fetched.
- GA_refresh_assets: remove "refresh" parameter. Now every call to
GA_refresh_assets will perform a network call to update the Liquid assets. To
avoid the network call use GA_get_assets. In addition GA_refresh_assets now
does not return any value, to get assets data use GA_get_assets.
- GA_get_assets: it is now possible to fetch information's via the `assets_id`
even before logging into a session.
- Removed support for LiquiDEX v0 for GA_create_swap_transaction,
GA_complete_swap_transaction and GA_validate, which now support LiquiDEX v1
only. LiquiDEX v0 transactions can still be created and completed with
GA_create_transaction.

### Fixed

### Removed

## Release 0.0.56 - 2022-10-03

### Added

- Added new function GA_decrypt_with_pin
- Added new function GA_validate
- Added new functions GA_create_swap_transaction and
  GA_complete_swap_transaction with support for LiquiDEX v0

### Changed

- GA_get_transactions: The input/output "addressee" element is now only populated for now-disabled historical social payments.
- GA_get_transactions: The top-level "satoshi" elements are now signed; negative values represent outgoing amounts.
- Singlesig: Stop stripping the witness from transactions, transaction hex returned from `get_transaction_details` will
return also the witness. Triggers a cache rebuild that could be noticeable from apps, seeing no transactions for a moment.
- GA_convert_amount: This can now be used to convert negative values.
- GA_get_wallet_identifier (and register/login): Now returns a network-agnostic version of "wallet_hash_id" as "xpub_hash_id".
- GA_create_transaction (and sign/send): The top-level "subaccount" type is no longer required or populated, and
"subaccount_type" is also no longer populated. The subaccount(s) the tx refers to are now inferred automatically
from its input UTXOs and output addressees.
- Singlesig: Exchange rates for the BTC-USD currency pair are now fetched from a
  Blockstream service.

### Fixed

- If the network connection drops in the middle of a request the latter will be
  eventually timed out instead of waiting for the connection to be available
  again.
- Fixed an issue where the Liquid asset registry would be re-downloaded
  every time `GA_refresh_assets` was called if the local registry file got corrupted.
- Fixed an issue where `GA_get_assets` would not return any assets if a
  wallet's Liquid cache file got corrupted.
- Singlesig: GA_get_transactions: Correctly handle "mixed" transactions
- Singlesig: Fixed a race condition, now after a block notification, all
  transactions are considering the last height.

### Removed

- JSON: remove "server_signed" from create/sign/send transaction JSON.
- JSON: remove "user_signed" from create/sign/send transaction JSON.
- GA_get_transactions: Remove the top-level "addressees" element. Callers should use the "address" elements of inputs and outputs instead.

## Release 0.0.55 - 2022-07-08

### Added

- Singlesig: Implement GA_get_previous_addresses
- Singlesig: Allow fetching internal addresses in GA_get_receive_address using "is_internal"=true
- Added new function GA_get_credentials, to replace GA_get_mnemonic_passphrase.
- Added new function GA_encrypt_with_pin, to replace GA_set_pin.
- Added new function GA_get_assets to query data related to a set of Liquid
  assets.
- Added bip39 passphrase support.

### Changed

- GA_get_previous_addresses: To get the newest generated addresses, caller should not include "last_pointer" key (instead of passing "last_pointer" 0). If the returned json does not have the "last_pointer" key, it indicates that all addresses have been fetched (previously it had "last_pointer" 1)
- GA_get_previous_addresses: Removed "subaccount" from returned keys.
- Singlesig: Add some missing fields to GA_get_receive_address returned json.
- Singlesig: Remove is_segwit from GA_get_unspent_outputs returned json
- GA_register_user: Change interface to match GA_login_user.
- Update endpoints for new bitcoin multisig backend.

### Fixed

- GA_get_unspent_outputs: fix bug returning utxos from replaced transactions.

### Removed

- Removed GA_get_mnemonic_passphrase, callers should use GA_get_credentials.
- Removed GA_set_pin, callers should use GA_encrypt_with_pin.
- Removed LTO and bitcode building flags.


## Release 0.0.54 - 2022-05-13

### Added

- Watch only: Support Liquid multisig watch-only logins
- Watch only: Allow deleting watch only accounts
- Watch only: Enable local caching for significantly faster performance
- Watch only: Support trust-on-first-use validation for xpubs and address generation
- Watch only: Initial support for transaction proposals (watch only tx creation)

### Changed

- Watch only: Re-enable viewing user metadata (account names, tx notes, hidden accounts) via client blob
- Watch only: Require usernames and passwords to each be at least 8 characters long
- Multisig: Remap non auth_handler call errors to support i18n

### Fixed

- Liquid: Fix unblinding when initially populating the local cache


## Release 0.0.53 - 2022-05-10

### Added

- Add build support for Apple M1

### Changed

- Changed transaction type from "unblindable" to "not unblindable" to reflect its actual meaning
- Move to Android ndk r23b LTS release
- Update openssl to 1.1.1n
- Update libwally to latest
- Rust is now mandatory for building
- Registry: Switched to unified implementation with full asset data. Only Liquid-BTC icon is hard-coded, only asset metadata having icons are hard-coded (38 assets)

### Fixed

- Singlesig: In GA_get_transactions "inputs" and "outputs" elements, set "address" and "address_type" correctly; do not set Liquid fields if not Liquid or not unblindable
- Singlesig: align transaction and block notifications with multisig
- Singlesig: temporarily lock spent utxos in the interval between send/broadcast and the next sync
- Singlesig: fix an error causing "restore" to fail


## Release 0.0.52 - 2022-04-22

### Added

- Support for sending to Liquid taproot addresses
- Documentation for GA_get_unspent_outputs result, including differences between singlesig and multisig.

### Changed

- Multisig: In GA_create_transaction "transaction_outputs" rename "public_key" to "blinding_key" when appropriate.
- Singlesig: In GA_create_transaction "transaction_outputs" make "is_change" equal to "is_internal", not "is_relevant"

### Fixed

- Singlesig: set GA_get_unspent_outputs result correctly and consistently with multisig.


## Release 0.0.51 - 2022-03-30

- SPV: Enable SPV for multisig BTC wallets
- Singlesig: support for HWW signers (Bitcoin only)
- Singlesig: support for GA_http_request
- Singlesig: implement GA_remove_account, see docs for details.


## Release 0.0.50 - 2022-03-08

- Documentation: Improve documentation for connection and network related functions, add documentation of each gdk notification type.
- Networking: Remove GA_disconnect.
- Networking: Multiple small ABI changes, please see the API documentation for details.
- Multisig/networking: Fix a number of bugs that could cause crashes and connection problems including failure to connect/reconnect.
- Singlesig/networking: Update to match the multisig interface, including notifications
- Misc: Various build and bug fixes


## Release 0.0.49 - 2022-01-20

- Singlesig: Improved account discovery
- Multisig: Don't send connection notifications for user-initiated session disconnect/destroy
- Multisig: Remove old support for passing addressee asset_id as asset_tag
- Multisig: Standardize address subtype as always 0 instead of null
- Multisig: Remove range and surjection proofs from returned UTXO data
- Multisig: Fix spending from very old version 0 addresses
- Liquid: Return blinded addresses in tx list results
- Liquid/AMP: Allow alternate blinding keys for AMP assets where required
- HWW interface: Change get_blinding_nonces to also return blinding keys
- Networking: fix some networking related crashes on android and iOS


## Release 0.0.48 - 2021-12-14

- Liquid: New experimental API GA_psbt_sign for partial signing
- Liquid: Update testnet asset registry URL
- Liquid: Disable multi-asset sends on all networks
- Liquid: Fix AMP blinding key upload on new subaccount creation
- Single sig: Randomize secp context before use
- All: Update localization strings
- Misc bug fixes


## Release 0.0.47.post1 - 2021-11-16

- Update Liquid Testnet URLs
- Fix create_subaccount bug


## Release 0.0.47 - 2021-11-04

- Multisig: add support for persistent transactions cache
- Multisig: return unblinded addresses in get_receive_address  and get_previous_addresses
- Singlesig: fix some json inconsistencies in transactions
- Add support for pay to taproot to both multisig and singlesig wallets (unavailable until activation on the main chain)


## Release 0.0.46.post1 - 2021-10-26

- Fix: increase proxy and socks setup timeouts
- Fix: tor wake-up


## Release 0.0.46 - 2021-10-19

- Single sig: Use built-in asset data if the asset registry is unreachable
- Single sig: Align create_transaction and get_transactions data more closely to multisig
- Single sig: Add support for manual coin selection
- Single sig: Improve TLS handling to allow connecting to more electrum servers
- Improve expired certificate handling
- Allow fetching wallet id without login and return it from register. Note the identifier returned by single sig sessions has changed to match multisig behavior
- Fix builds under Python 3.9


## Release 0.0.45.post1 - 2021-09-29

Patched version from v0.0.45 with:

- Remove expired LE certificates


## Release 0.0.45 - 2021-09-22

- ABI: Explicit utxos on create_transaction
- Network: Improved re-login mechanism
- General: Improved call handler resolution to reduce many requests
- General: Improved caching for HWW
- Singlesig: Improved create transaction and support bip21 prefix


## Release 0.0.44 - 2021-09-01

- Single sig: Enable Bitcoin mainnet support
- Liquid: Add support for host unblinding
- Liquid: Provide fallback built-in asset and icon data
- Network: Stability and re-connection improvements
- ABI: Add fiat rate change notifications, remove fee notifications
- ABI: Add GA_get_fee_estimates to fetch fees
- ABI: Add new filter options (dust, expiry, confidential) for balances/UTXOs
- ABI: Remove GA_get_expired_deposits
- ABI: Simplify and document the hardware wallet/auth handler interfaces
- ABI: There are now fewer state changes for some auth handlers
- General: Improved caching to speed up many operations
- General: Various bug fixes and speedups


## Release 0.0.43.post1 - 2021-08-12

Patched version from v0.0.43 with:
- rust: update aes related dependencies
- rust: update MSRV to 1.49.0
- ci: update docker images


## Release 0.0.43 - 2021-06-29

- Single sig: Fix an issue with address generation for p2wpkh/p2pkh that could cause stuck coins
- Single sig: Many important fixes and improvements to upcoming single sig support, including Fee bumping and tx eviction support, improved Liquid fee estimation, faster operation, more consistency with multisig and test improvements
- Single sig: Multiple ABI changes including the location of cached data and settings which will not be carried forward. Please note the single sig code will continue to change rapidly until mainnet release including potentially further ABI changes
- Network: New Liquid Testnet network is now supported
- Network: Add a new certificate chain to replace the current chain which will expire soon
- Network: Upgrade asset registry and backend onion connections to tor v3
- Build: Multiple build fixes and dependency updates
- Build: Add support for building on Apple Big Sur
- ABI: removed GA_check_proxy_connectivity
- ABI: Liquid now uses the networks policy asset id instead of "btc" in returned JSON
- ABI: The sequence of state changes for some auth handlers has changed
- ABI: GA_login_user should be used for all logins. The existing login calls will be removed in the next release
- ABI: Network parameter names and some keys have changed names for consistency.
- General: Various bug fixes and internal consistency improvements


## Release 0.0.42 post1 - 2021-06-01

Patched version from v0.0.42 with:
- rust: fix db dir name
- update meson to 0.58.0
- update boost and autobahn-cpp
- fix builds on darwin system


## Release 0.0.42 - 2021-05-16

- Rust: Add support for multiple accounts and multiple types (p2sh-p2wpkh, p2wpkh, p2pkh)
- Rust: Perform BIP44 account discovery at first login
- Rust: Spend unconfidential utxos by default
- Rust: Add support for proxy network connections
- Rust: Standardize wallet identification and caching behavior
- Rename some electrum network names (breaking change)
- Add GA_login_user to replace other login calls, which are now deprecated.
- Update root certificates for SSL certificate pinning validation
- Networking fixes
- Build and CI fixes


## Release 0.0.41 - 2021-03-29

- Add support for the hardware anti-exfil protocol
- Add support for undoing a two factor reset request
- Add support for multi-server SPV cross-validation under electrum
- Add support for hiding accounts and renaming the main account
- Add support for fetching historical addresses
- Add Python examples for Bitcoin and Liquid AMP assets
- Bug fixes, thread safety improvements and updates


## Release 0.0.40 - 2021-02-12

- Liquid: Fix un-blindable transaction handling
- Show subaccount names and transaction memos for non-blob-upgraded wallets
- Remove the limit on transaction list fetching for large numbers of transactions
- Threading safety improvements, bug fixes


## Release 0.0.39 - 2021-02-02

- add client blob support to store encrypted data on the server, use it to store tx memos and subaccount names
- 2of3: sign recovery key at subaccount creation, later verify it
- handle missing fiat rate
- validate replace transactions
- reformat user agent string


## Release 0.0.38 - 2021-01-14

fiat rate fixes


## Release 0.0.37 - 2021-01-02

updates let's encrypt CA certs


## Release 0.0.36 - 2020-12-03

- fix python builds on OSX builder
- update rust unit test
- correctly initialize logging level
- improve SPV validation
- fix sign_message for hw ack_system_message
- use correct serialization for blinders (breaking change 468197f029484d2060c07c6ab780adde31a2279a)
- fix JNI/clang 11 build
- enable bitcode on libwally build
- bump cache version



## Release 0.0.35 - 2020-10-27

- add support for Electrum sessions (mainnet, testnet, regtest, liquid, liquid regtest)
- fixes for csv type scripts
- add new `set_unspent_outputs_status` call to change a UTXOs status
- update wally to latest


## Release 0.0.34 - 2020-08-26

- update dependencies: sqlite and nlohmann json
- update key "satoshi" in transaction json on asset_tag
- watch-only: handle missing nlocktime_blocks
- remove unnecessary call to get_blinded_scripts
- upload_confidential_addresses: Fix unlocked access, avoid pass-by-value


## Release 0.0.33 - 2020-07-08

- Update login_with_pin() to return a resolver
- On Login, upload "required_ca" confidential addresses
- Allow caller to override GA_http_request timeout
- During liquid create transaction: clear error utxos, add change addresses to tx earlier, get blinding nonces
- Improvements to handling of http requests, allow caller to pass custom root certificates to GA_http_request
- Makes httpget more generally useful with graceful close of tls connection


## Release 0.0.32 - 2020-06-12

- Replace GA_http_get with GA_http_request, which can perform POST as well as
  GET. Urls are specified as a set from which the gdk will choose the most
  appropriate, e.g. if the session is running tor and an onion url is present it
  will get preference over a non-onion url.
- Add GA_generate_mnemonic_12
- Enable ccache by default if ccache is found
- Build improvements
- Bug fixing


## Release 0.0.31 - 2020-05-14

- Allow caller to pass xpub to create a 2of3 account
- Use legacy derivation for 2of3 recovery xpubs
- Disable multi-asset send in liquid mainnet
- Enable setting nlocktime via GA_change_settings
- Refactor appearance settings mapping
- Update openssl to 1.1.1g



## Release 0.0.30 - 2020-04-13

- update travis windows build and osx meson version
- fix sending to liquid blech32 addresses
- update docker images and rust version
- update libwally, tor, openssl, gls library


## Release 0.0.29 - 2020-03-30

Increase rangeproof ct bits from 36 to 52


## Release 0.0.28 - 2020-02-27

- represent missing fiat rate as null in amount json
- gracefully handle invalid value for fiat rate
- asset Id validation on bip21 uri


## Release 0.0.27 - 2020-02-03

- add bip21 uri for liquid
- update swift bindings
- bug fixes
