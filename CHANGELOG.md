# Changelog

## Release 0.0.55

### Added

- Singlesig: Implement GA_get_previous_addresses
- Singlesig: Allow fetching internal addresses in GA_get_receive_address using "is_internal"=true

### Changed

- GA_get_previous_addresses: To get the newest generated addresses, caller should not include "last_pointer" key (instead of passing "last_pointer" 0). If the returned json does not have the "last_pointer" key, it indicates that all addresses have been fetched (previously it had "last_pointer" 1)
- GA_get_previous_addresses: Removed "subaccount" from returned keys.
- Singlesig: Add some missing fields to GA_get_receive_address returned json.


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
- Registry: Switched to unified implementation with full asset data. Only Liquid-BTC icon is hardcoded, only asset metadata having icons are hardcoded (38 assets)

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
- Singlesig: support for hw signers (Bitcoin only)
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
- Multisig: Standardise address subtype as always 0 instead of null
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
- All: Update localisation strings
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
- Fix: tor wakeup


## Release 0.0.46 - 2021-10-19

- Single sig: Use built-in asset data if the asset registry is unreachable
- Single sig: Align create_transaction and get_transactions data more closely to multisig
- Single sig: Add support for manual coin selection
- Single sig: Improve TLS handling to allow connecting to more electrum servers
- Improve expired certificate handling
- Allow fetching wallet id without login and return it from register. Note the identifier returned by single sig sessions has changed to match multisig behaviour
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
