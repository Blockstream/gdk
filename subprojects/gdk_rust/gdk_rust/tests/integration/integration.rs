use std::collections::HashMap;
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
use electrsd::electrum_client::ElectrumApi;
use gdk_common::bitcoin::util::bip32::DerivationPath;
use gdk_common::bitcoin::Witness;
use gdk_common::log::info;
use serde_json::Value;
use tempfile::TempDir;

use gdk_common::be::BETransaction;
use gdk_common::model::*;
use gdk_common::scripts::ScriptType;
use gdk_common::session::Session;
use gdk_common::{NetworkId, NetworkParameters, State};
use gdk_electrum::error::Error;
use gdk_electrum::headers::bitcoin::HeadersChain;
use gdk_electrum::interface::ElectrumUrl;
use gdk_electrum::{headers, spv, ElectrumSession};
use gdk_test::utils;
use gdk_test::{ElectrumSessionExt, TestSession};

static MEMO1: &str = "hello memo";
static MEMO2: &str = "hello memo2";

#[test]
fn roundtrip_bitcoin_1() {
    let mut test_session = TestSession::new(false, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));

    test_session.fund(100_000_000, None);

    let txid = test_session.send_tx(
        &node_address,
        10_000,
        None,
        Some(MEMO1.to_string()),
        None,
        None,
        None,
    ); // p2shwpkh
    test_session.mine_block();
    test_session.test_set_get_memo(&txid, MEMO1, MEMO2);
    test_session.send_multi(3, 100_000, &vec![]);
    test_session.send_multi(30, 100_000, &vec![]);
    test_session.mine_block();
    test_session.fees();
    test_session.settings();
    test_session.is_verified(&txid, SPVVerifyTxResult::Verified);
    test_session.spv_verify_tx(&txid, 102, Some(1));
    test_session.reconnect();
    test_session.test_set_get_memo(&txid, MEMO2, ""); // after reconnect memo has been reloaded from disk

    test_session.stop();
}

#[test]
fn roundtrip_bitcoin_2() {
    let mut test_session = TestSession::new(false, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));
    let node_bech32_address = test_session.node_getnewaddress(Some("bech32"));
    let node_legacy_address = test_session.node_getnewaddress(Some("legacy"));

    test_session.fund(100_000_000, None);
    // We have a single transaction so far, so we expect exactly 1 tx notification
    let events = test_session.session.filter_events("transaction");
    assert_eq!(events.len(), 1);

    test_session.get_subaccount();
    let txid = test_session.send_tx(
        &node_address,
        10_000,
        None,
        Some(MEMO1.to_string()),
        None,
        None,
        None,
    ); // p2shwpkh
    test_session.is_verified(&txid, SPVVerifyTxResult::Unconfirmed);
    test_session.send_tx(&node_bech32_address, 10_000, None, None, None, None, None); // p2wpkh
    test_session.send_tx(&node_legacy_address, 10_000, None, None, None, None, None); // p2pkh
    test_session.send_all(&node_legacy_address, None);
    test_session.mine_block();
    test_session.send_tx_same_script();

    let utxos = test_session.utxo("btc", vec![149739]);
    test_session.check_decryption(102, &[&txid]);

    test_session.send_tx(&node_legacy_address, 10_000, None, None, Some(utxos), None, None);
    test_session.utxo("btc", vec![139569]); // the smallest utxo has been spent
                                            // TODO add a test with external UTXO}
}

#[test]
fn roundtrip_liquid_1() {
    let mut test_session = TestSession::new(true, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));

    let assets = test_session.fund(100_000_000, Some(3));

    test_session.receive_unconfidential();
    test_session.get_subaccount();

    let txid = test_session.send_tx(
        &node_address,
        10_000,
        None,
        Some(MEMO1.to_string()),
        None,
        None,
        None,
    );
    test_session.mine_block();
    test_session.test_set_get_memo(&txid, MEMO1, MEMO2);
    test_session.send_multi(3, 100_000, &vec![]);
    test_session.send_multi(30, 100_000, &assets);
    test_session.fees();
    test_session.settings();
    test_session.is_verified(&txid, SPVVerifyTxResult::Verified);
    test_session.spv_verify_tx(&txid, 102, Some(1));
    test_session.reconnect();
    test_session.test_set_get_memo(&txid, MEMO2, "");

    test_session.utxo(&assets[0], vec![99000000]);

    test_session.stop();
}

#[test]
fn roundtrip_liquid_2() {
    let mut test_session = TestSession::new(true, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));
    let node_bech32_address = test_session.node_getnewaddress(Some("bech32"));
    let node_legacy_address = test_session.node_getnewaddress(Some("legacy"));

    let assets = test_session.fund(100_000_000, Some(1));

    let txid = test_session.send_tx(
        &node_address,
        10_000,
        None,
        Some(MEMO1.to_string()),
        None,
        None,
        None,
    );

    test_session.check_decryption(101, &[&txid]);
    test_session.is_verified(&txid, SPVVerifyTxResult::Unconfirmed);
    test_session.send_tx(&node_bech32_address, 10_000, None, None, None, None, None);
    test_session.send_tx(&node_legacy_address, 10_000, None, None, None, None, None);
    test_session.send_tx(&node_address, 10_000, Some(assets[0].clone()), None, None, None, None);
    test_session.send_tx(&node_address, 100, Some(assets[0].clone()), None, None, None, None); // asset should send below dust limit
    test_session.send_all(&node_address, Some(assets[0].to_string()));
    test_session.send_all(&node_address, test_session.asset_id());
    test_session.mine_block();

    test_session.fund(1_000_000, None);

    let utxos = test_session
        .utxo("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225", vec![1_000_000]);

    test_session.send_tx(&node_legacy_address, 10_000, None, None, Some(utxos), None, None);

    test_session
        .utxo("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225", vec![989740]); // the smallest utxo has been spent

    // test_session.check_decryption(103, &[&txid]); // TODO restore after sorting out https://github.com/ElementsProject/rust-elements/pull/61

    test_session.stop();
}

fn check_account_balances(test_session: &TestSession, balances: &HashMap<u32, u64>) {
    for (n, balance) in balances {
        assert_eq!(test_session.balance_account(*n, None, None), *balance);
    }
}

#[test]
fn create_tx_err_bitcoin() {
    create_tx_err(false);
}

#[test]
fn create_tx_err_liquid() {
    create_tx_err(true);
}

fn create_tx_err(is_liquid: bool) {
    let mut test_session = TestSession::new(is_liquid, |_| ());

    let addr = test_session.node_getnewaddress(None);
    let fee_rate = None;
    let subaccount = 0;
    let asset_id = test_session.asset_id();
    let sat = 1000;

    // Amount 0
    let mut create_opt = test_session.create_opt(
        &addr,
        0,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidAmount)
    ));

    // Amount below dust
    let mut create_opt = test_session.create_opt(
        &addr,
        200,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidAmount)
    ));

    // No utxos passed
    let mut create_opt = test_session.create_opt(
        &addr,
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        GetUnspentOutputs::default(),
    );
    assert!(create_opt.utxos.iter().all(|(_, v)| v.len() == 0));
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InsufficientFunds)
    ));

    // Not enough to pay the fee
    let wallet_sat = 5000;
    let wallet_address = test_session.get_receive_address(0).address;
    let txid = test_session.node_sendtoaddress(&wallet_address, wallet_sat, None);
    test_session.wait_tx(vec![0], &txid, Some(wallet_sat), Some(TransactionType::Incoming));
    let mut create_opt = test_session.create_opt(
        &addr,
        wallet_sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InsufficientFunds)
    ));

    // Invalid subaccount
    let mut create_opt =
        test_session.create_opt(&addr, sat, asset_id.clone(), fee_rate, 99, test_session.utxos(0));
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidSubaccount(_))
    ));

    // Fee rate below minimum
    let mut create_opt = test_session.create_opt(
        &addr,
        sat,
        asset_id.clone(),
        Some(99),
        subaccount,
        test_session.utxos(0),
    );
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::FeeRateBelowMinimum(_))
    ));

    // Not an address
    let mut create_opt = test_session.create_opt(
        &"x",
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidAddress)
    ));

    // Wrong networks
    let wrong_net_addr = if is_liquid {
        // regtest bitcoin
        "mxvewdhKCenLkYgNa8irv1UM2omEWPMdEE"
    } else {
        // regtest liquid
        "AzpwMmJacz8ngdJszGjNeNBeQ2iu5qNYWpZfkqBoZU6acK6tSbEdpt9PsWdRtcb2pxAQcdTySE4KmhJk"
    };
    let mut create_opt = test_session.create_opt(
        &wrong_net_addr,
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidAddress)
    ));

    let mainnet_addr = if is_liquid {
        "VJLCbLBTCdxhWyjVLdjcSmGAksVMtabYg15maSi93zknQD2ihC38R7CUd8KbDFnV8A4hiykxnRB3Uv6d"
    } else {
        "38CMdevthTKYAtxaSkYYtcv5QgkHXdKKk5"
    };
    let mut create_opt = test_session.create_opt(
        &mainnet_addr,
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidAddress)
    ));

    // Segwitv1 and b(l)ech32
    let segwitv1_addr = if is_liquid {
        "el1pq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfsxguu9nrdg2pc"
    } else {
        "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqdmchcc"
    };
    let mut create_opt = test_session.create_opt(
        &segwitv1_addr,
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidAddress)
    ));

    // Segwitv1 and b(l)ech32m
    let segwitv1_addr = if is_liquid {
        "el1pqdw8vgncs6ep0e4vcllwcvt8kr7z5e45z3qr4wsvnnq2qatsm3ejws3ylj93nn9qw0w7e5p20m06mp7hp33kt56nt0jtlw39md63p00wj7v4j5vahy5l"
    } else {
        "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
    };
    let mut create_opt = test_session.create_opt(
        &segwitv1_addr,
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );

    test_session.session.create_transaction(&mut create_opt).unwrap();

    // Segwitv1 and b(l)ech32m, but len != 32
    let segwitv1_addr = if is_liquid {
        "el1pq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq87gd2ckgcugl"
    } else {
        "bcrt1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k0ylj56"
    };
    let mut create_opt = test_session.create_opt(
        &segwitv1_addr,
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );

    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidAddress)
    ));

    // Segwitv2 and b(l)ech32m
    let segwitv1_addr = if is_liquid {
        "el1zq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqg3sqzyqnv9cq"
    } else {
        "bcrt1zw508d6qejxtdg4y5r3zarvaryv2wuatf"
    };
    let mut create_opt = test_session.create_opt(
        &segwitv1_addr,
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );

    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InvalidAddress)
    ));

    if is_liquid {
        // Unblinded
        let unconf_addr = utils::to_unconfidential(&addr);
        let mut create_opt = test_session.create_opt(
            &unconf_addr,
            sat,
            asset_id.clone(),
            fee_rate,
            subaccount,
            test_session.utxos(0),
        );
        assert!(matches!(
            test_session.session.create_transaction(&mut create_opt),
            Err(Error::NonConfidentialAddress)
        ));

        // Missing asset_id
        let mut create_opt =
            test_session.create_opt(&addr, sat, None, fee_rate, subaccount, test_session.utxos(0));
        assert!(matches!(
            test_session.session.create_transaction(&mut create_opt),
            Err(Error::InvalidAssetId)
        ));

        // Invalid asset_id
        let mut create_opt = test_session.create_opt(
            &addr,
            sat,
            Some("xyz".to_string()),
            fee_rate,
            subaccount,
            test_session.utxos(0),
        );
        assert!(matches!(
            test_session.session.create_transaction(&mut create_opt),
            Err(Error::InvalidAssetId)
        ));
    }

    // EmptyAddressees
    let mut create_opt = test_session.create_opt(
        &addr,
        sat,
        asset_id.clone(),
        fee_rate,
        subaccount,
        test_session.utxos(0),
    );
    create_opt.addressees.clear();
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::EmptyAddressees)
    ));
}

#[test]
fn coin_selection_bitcoin() {
    coin_selection(false);
}

#[test]
fn coin_selection_liquid() {
    coin_selection(true);
}

fn coin_selection(is_liquid: bool) {
    let mut test_session = TestSession::new(is_liquid, |_| ());

    // Fund the wallet with 2 coins
    let sat1 = 10_000;
    let addr1 = test_session.get_receive_address(0).address;
    let txid1 = test_session.node_sendtoaddress(&addr1, sat1, None);
    test_session.wait_tx(vec![0], &txid1, Some(sat1), Some(TransactionType::Incoming));
    test_session.mine_block();
    let sat2 = 20_000;
    let addr2 = test_session.get_receive_address(0).address;
    let txid2 = test_session.node_sendtoaddress(&addr2, sat2, None);
    test_session.wait_tx(vec![0], &txid2, Some(sat2), Some(TransactionType::Incoming));
    test_session.mine_block();

    // Pass 2 utxos, but use one
    let btc_key = test_session.btc_key();
    let utxos = test_session.utxo(&btc_key, vec![sat1, sat2]);
    let sat3 = 1_000;
    let node_address = test_session.node_getnewaddress(None);
    let txid3 = test_session.send_tx(
        &node_address,
        sat3,
        None,
        None,
        Some(utxos),
        None,
        Some(UtxoStrategy::Default),
    );
    let sat4 = sat2 - sat3 - test_session.get_tx_from_list(0, &txid3).fee;
    let mut utxos = test_session.utxo(&btc_key, vec![sat1, sat4]);

    // send_all passing one utxo
    utxos.0.get_mut(&btc_key).unwrap().retain(|e| e.satoshi == sat4);
    let node_address = test_session.node_getnewaddress(None);
    assert_eq!(utxos.0.get(&btc_key).unwrap().len(), 1);
    test_session.send_all_from_account(
        0,
        &node_address,
        None,
        Some(utxos),
        Some(UtxoStrategy::Default),
    );
    test_session.utxo(&btc_key, vec![sat1]);

    // Receive another coin
    let sat5 = 30_000;
    let addr = test_session.get_receive_address(0).address;
    let txid = test_session.node_sendtoaddress(&addr, sat5, None);
    test_session.wait_tx(vec![0], &txid, Some(sat5), Some(TransactionType::Incoming));
    test_session.mine_block();

    // Pass 2 utxos and send both with "manual"
    let utxos = test_session.utxo(&btc_key, vec![sat1, sat5]);
    let sat6 = 1_000;
    let node_address = test_session.node_getnewaddress(None);
    let txid = test_session.send_tx(
        &node_address,
        sat6,
        None,
        None,
        Some(utxos.clone()),
        None,
        Some(UtxoStrategy::Manual),
    );
    let fee = test_session.get_tx_from_list(0, &txid).fee;
    // every output could have covered the amount to send plus fee, but we used both of them
    assert!(utxos.0.get(&btc_key).unwrap().iter().all(|u| sat6 + fee < u.satoshi));
    let sat7 = sat1 + sat5 - sat6 - fee;
    test_session.utxo(&btc_key, vec![sat7]);

    // If "manual", passing 0 utxos will cause an insufficient funds error
    let mut create_opt = CreateTransaction::default();
    let sat8 = 1_000;
    assert!(sat8 < sat7);
    create_opt.addressees.push(AddressAmount {
        address: node_address.to_string(),
        satoshi: sat8,
        asset_id: test_session.asset_id(),
    });
    create_opt.utxos = CreateTxUtxos::default();
    create_opt.utxo_strategy = UtxoStrategy::Manual;
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InsufficientFunds)
    ));

    if is_liquid {
        // Receive asset
        let sat1_a = 10_000;
        let addr = test_session.get_receive_address(0).address;
        let (asset_a, txid) = test_session.fund_asset(sat1_a, &addr);
        test_session.wait_tx(vec![0], &txid, None, None);
        let mut utxos = test_session.utxo(&asset_a, vec![sat1_a]);

        // If passing utxos explicitly, send with asset requires some l-btc asset to be passed as
        // well
        let mut create_opt = CreateTransaction::default();
        let sat2_a = 1_000;
        assert!(sat2_a < sat1_a);
        create_opt.addressees.push(AddressAmount {
            address: node_address.to_string(),
            satoshi: sat2_a,
            asset_id: Some(asset_a.clone()),
        });
        utxos.0.remove_entry(&btc_key);
        create_opt.utxos = utils::convertutxos(&utxos);
        create_opt.utxo_strategy = UtxoStrategy::Manual;
        assert!(matches!(
            test_session.session.create_transaction(&mut create_opt),
            Err(Error::InsufficientFunds)
        ));

        // send_all with asset does not send all l-btc
        let utxos = test_session.utxo(&asset_a, vec![sat1_a]);
        let node_address = test_session.node_getnewaddress(None);
        let (_, _, fee) = test_session.send_all_from_account(
            0,
            &node_address,
            Some(asset_a.clone()),
            Some(utxos),
            Some(UtxoStrategy::Default),
        );
        let sat9 = sat7 - fee;
        test_session.utxo(&btc_key, vec![sat9]);
        test_session.utxo(&asset_a, vec![]);

        // Fund the wallet so that it has 3 assets (including l-btc) and 2 coins per asset.
        test_session.mine_block();

        let sat2_a = 2;
        let sat3_a = 3;
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat2_a, Some(&asset_a));
        test_session.wait_tx(vec![0], &txid, None, None);
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat3_a, Some(&asset_a));
        test_session.wait_tx(vec![0], &txid, None, None);

        let sat1_b = 10;
        let asset_b = test_session.node_issueasset(sat1_b);
        let sat2_b = 2;
        let sat3_b = 3;
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat2_b, Some(&asset_b));
        test_session.wait_tx(vec![0], &txid, None, None);
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat3_b, Some(&asset_b));
        test_session.wait_tx(vec![0], &txid, None, None);

        let sat10 = 20_000;
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat10, None);
        test_session.wait_tx(vec![0], &txid, None, None);

        test_session.utxo(&asset_a, vec![sat2_a, sat3_a]);
        test_session.utxo(&asset_b, vec![sat2_b, sat3_b]);
        let utxos = test_session.utxo(&btc_key, vec![sat9, sat10]);

        test_session.mine_block();

        // "manual" uses all utxos, for every asset even if they are not among the addressees, de
        // facto consolidating them.
        let sat4_a = 1;
        assert!(utxos.0.get(&asset_a).unwrap().iter().all(|u| sat4_a < u.satoshi));
        let node_address = test_session.node_getnewaddress(None);
        let txid = test_session.send_tx(
            &node_address,
            sat4_a,
            Some(asset_a.clone()),
            None,
            Some(utxos.clone()),
            None,
            Some(UtxoStrategy::Manual),
        );
        let fee = test_session.get_tx_from_list(0, &txid).fee;
        let sat11 = sat9 + sat10 - fee;
        let sat5_a = sat2_a + sat3_a - sat4_a;
        let sat4_b = sat2_b + sat3_b;
        test_session.utxo(&btc_key, vec![sat11]);
        test_session.utxo(&asset_a, vec![sat5_a]);
        test_session.utxo(&asset_b, vec![sat4_b]);
    }
}

#[test]
fn subaccounts_bitcoin() {
    subaccounts(false);
}

#[test]
fn subaccounts_liquid() {
    subaccounts(true);
}

fn subaccounts(is_liquid: bool) {
    let mut test_session = TestSession::new(is_liquid, |_| ());

    let account0 = test_session.session.get_subaccount(0).unwrap();
    let n_txs =
        test_session.session.get_transactions(&GetTransactionsOpt::default()).unwrap().0.len();
    assert_eq!(n_txs, 0);
    assert_eq!(account0.bip44_discovered, false);
    assert!(test_session.session.get_subaccount(1).is_err());

    // Create subaccounts
    let account1 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 1,
            name: "Account 1".into(),
            ..Default::default() // p2wpkh
        })
        .unwrap();
    let account2 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 2,
            name: "Account 2".into(),
            ..Default::default() // p2pkh
        })
        .unwrap();
    assert_eq!(account1.account_num, 1);
    assert_eq!(account1.settings.name, "Account 1");
    assert_eq!(account1.script_type, ScriptType::P2wpkh);
    assert_eq!(account1.settings.hidden, false);
    assert_eq!(account1.bip44_discovered, false);
    assert_eq!(account2.account_num, 2);
    assert_eq!(account2.settings.name, "Account 2");
    assert_eq!(account2.script_type, ScriptType::P2pkh);
    assert_eq!(account2.settings.hidden, false);
    assert_eq!(account2.bip44_discovered, false);
    assert_eq!(test_session.session.get_subaccount(1).unwrap().script_type, ScriptType::P2wpkh);
    assert_eq!(test_session.session.get_subaccount(2).unwrap().settings.name, "Account 2");

    // Update subaccount settings
    test_session
        .session
        .update_subaccount(UpdateAccountOpt {
            subaccount: 2,
            hidden: Some(true),
            ..Default::default()
        })
        .unwrap();
    let acc2 = test_session.session.get_subaccount(2).unwrap();
    assert_eq!(acc2.settings.hidden, true);
    // update_subaccount should not affect unspecified fields
    assert_eq!(acc2.settings.name, "Account 2");

    // Rename subaccount (deprecated in favor of update_subaccount)
    test_session
        .session
        .rename_subaccount(RenameAccountOpt {
            subaccount: 2,
            new_name: "Account 2@".into(),
        })
        .unwrap();
    assert_eq!(test_session.session.get_subaccount(2).unwrap().settings.name, "Account 2@");

    // Get addresses & check they match the expected types
    let acc0_address = test_session.get_receive_address(0);
    let acc1_address = test_session.get_receive_address(1);
    let acc2_address = test_session.get_receive_address(2);

    if is_liquid {
        assert!(acc0_address.address.starts_with("A")); // P2SH-P2WSH
        assert!(acc1_address.address.starts_with("el1")); // Native Bech32 P2WPKH
        assert!(acc2_address.address.starts_with("CT")); // Legacy P2PKH
    } else {
        assert!(acc0_address.address.starts_with("2")); // P2SH-P2WSH
        assert!(acc1_address.address.starts_with("bcrt1")); // Native Bech32 P2WPKH
        assert!(acc2_address.address.starts_with(&['m', 'n'][..])); // Legacy P2PKH
    }
    let s = |v| DerivationPath::from(v).to_string();
    assert_eq!(s(acc0_address.user_path), "m/49'/1'/0'/0/1");
    assert_eq!(s(acc1_address.user_path), "m/84'/1'/0'/0/1");
    assert_eq!(s(acc2_address.user_path), "m/44'/1'/0'/0/1");

    let mut balances: HashMap<u32, u64> = HashMap::new();

    // Send some to account #1
    let sat = 98766;
    let txid = test_session.node_sendtoaddress(&acc1_address.address, sat, None);
    test_session.wait_tx(vec![1], &txid, Some(sat), Some(TransactionType::Incoming));
    *balances.entry(1).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);
    assert_eq!(test_session.session.get_subaccount(1).unwrap().bip44_discovered, true);

    // Send some to account #2
    let sat = 67899;
    let txid = test_session.node_sendtoaddress(&acc2_address.address, sat, None);
    test_session.wait_tx(vec![2], &txid, Some(sat), Some(TransactionType::Incoming));
    *balances.entry(2).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);
    assert_eq!(test_session.session.get_subaccount(2).unwrap().bip44_discovered, true);

    // Send all from account #2 to account #1 (p2pkh -> p2wpkh)
    let (txid, _, fee) = test_session.send_all_from_account(
        2,
        &test_session.get_receive_address(1).address,
        None,
        None,
        None,
    );
    test_session.wait_tx(vec![1, 2], &txid, Some(sat - fee), Some(TransactionType::Incoming));
    *balances.entry(1).or_insert(0) += sat - fee;
    *balances.entry(2).or_insert(0) = 0;
    check_account_balances(&test_session, &balances);
    assert_eq!(test_session.session.get_subaccount(1).unwrap().bip44_discovered, true);

    // Send from account #1 to account #0 (p2wpkh -> p2sh-p2wpkh)
    let sat = 11555;
    let (txid, fee) = test_session.send_tx_from(1, &acc0_address.address, sat, None);
    test_session.wait_tx(vec![0, 1], &txid, Some(sat), Some(TransactionType::Incoming));
    *balances.entry(1).or_insert(0) -= sat + fee;
    *balances.entry(0).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);
    // can_rbf is true iff the subaccount can replace the transaction
    let tx0 = test_session.get_tx_from_list(0, &txid);
    let tx1 = test_session.get_tx_from_list(1, &txid);
    if is_liquid {
        assert!(!tx0.rbf_optin && !tx1.rbf_optin && !tx0.can_rbf && !tx1.can_rbf);
    } else {
        assert!(tx0.rbf_optin && tx1.rbf_optin && !tx0.can_rbf && tx1.can_rbf);
    }

    // Send from account #0 to account #2 (p2sh-p2wpkh -> p2pkh)
    let sat = 1000;
    let (txid, fee) =
        test_session.send_tx_from(0, &test_session.get_receive_address(2).address, sat, None);
    test_session.wait_tx(vec![0, 2], &txid, Some(sat + fee), Some(TransactionType::Outgoing));
    *balances.entry(0).or_insert(0) -= sat + fee;
    *balances.entry(2).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);

    // Must be created using the next available P2PKH account number (skipping over used and reserved numbers)
    let account3 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 18,
            name: "Second PKPH".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(account3.script_type, ScriptType::P2pkh);
    assert_eq!(test_session.session.get_subaccount(18).unwrap().bip44_discovered, false);

    let acc18_address = test_session.get_receive_address(18);
    assert_eq!(s(acc18_address.user_path), "m/44'/1'/1'/0/1");

    // Should fail - the second P2PKH account is still inactive
    let err = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 34,
            name: "Won't work".into(),
            ..Default::default()
        })
        .unwrap_err();
    assert!(matches!(err, Error::AccountGapsDisallowed));

    // Fund the second P2PKH account, skipping over one address
    let sat = 6666;
    test_session.get_receive_address(18);
    let (txid, fee) =
        test_session.send_tx_from(0, &test_session.get_receive_address(18).address, sat, None);
    test_session.wait_tx(vec![0, 18], &txid, Some(sat + fee), Some(TransactionType::Outgoing));
    *balances.entry(0).or_insert(0) -= sat + fee;
    *balances.entry(18).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);
    assert_eq!(test_session.session.get_subaccount(18).unwrap().bip44_discovered, true);

    // Should now work
    let account4 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 34,
            name: "Third PKPH".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(account4.script_type, ScriptType::P2pkh);
    let address = test_session.get_receive_address(34);
    let sat = 1_000;
    let (txid, fee) = test_session.send_tx_from(0, &address.address, sat, None);
    test_session.wait_tx(vec![0, 34], &txid, Some(sat + fee), Some(TransactionType::Outgoing));
    *balances.entry(34).or_insert(0) += sat;
    *balances.entry(0).or_insert(0) -= sat + fee;

    assert_eq!(s(account0.user_path), "m/49'/1'/0'");
    assert_eq!(s(account1.user_path), "m/84'/1'/0'");
    assert_eq!(s(account2.user_path), "m/44'/1'/0'");
    assert_eq!(s(account3.user_path), "m/44'/1'/1'");
    assert_eq!(s(account4.user_path), "m/44'/1'/2'");

    if !is_liquid {
        assert!(account0.slip132_extended_pubkey.unwrap().starts_with("upub"));
        assert!(account1.slip132_extended_pubkey.unwrap().starts_with("vpub"));
        assert!(account2.slip132_extended_pubkey.unwrap().starts_with("tpub"));
        assert!(account3.slip132_extended_pubkey.unwrap().starts_with("tpub"));
        assert!(account4.slip132_extended_pubkey.unwrap().starts_with("tpub"));
    }

    for subaccount in test_session.session.get_subaccounts().unwrap() {
        test_session.check_address_from_descriptor(subaccount.account_num);
    }

    // Test get_next_subaccount
    let next_p2pkh = test_session
        .session
        .get_next_subaccount(GetNextAccountOpt {
            script_type: ScriptType::P2pkh,
        })
        .unwrap();
    assert_eq!(next_p2pkh, 50);

    // Start a new session, using the same mnemonic and electrum server, but
    // with a brand new database -- unaware of our subaccounts.
    let mut new_session = {
        let mut network = test_session.network_parameters().clone();
        let temp_dir = TempDir::new().unwrap();
        network.state_dir = format!("{}", temp_dir.path().display());
        ElectrumSession::new(network).unwrap()
    };

    let credentials = test_session.credentials.clone();
    new_session.auth_handler_login(&credentials);

    let subaccounts = new_session.get_subaccounts().unwrap();
    assert_eq!(subaccounts.len(), 1);
    assert!(new_session.get_subaccount(0).is_ok());

    new_session.discover_subaccounts(&credentials);
    let subaccounts = new_session.get_subaccounts().unwrap();
    assert_eq!(subaccounts.len(), balances.len());
    assert_eq!(new_session.get_subaccount(0).unwrap().bip44_discovered, true);
    assert_eq!(new_session.get_subaccount(1).unwrap().bip44_discovered, true);
    assert_eq!(new_session.get_subaccount(2).unwrap().bip44_discovered, true);
    assert_eq!(new_session.get_subaccount(18).unwrap().bip44_discovered, true);

    // Check refresh option in get_subaccounts see an account created (with a tx) in another session
    // creating in test_session, verifying is discovered in new_session
    let new_account = 17;
    assert!(new_session.get_subaccount(new_account).is_err());
    let account_opt = CreateAccountOpt {
        subaccount: new_account,
        name: "next_p2pkh".to_string(),
        ..Default::default()
    };
    test_session.session.create_subaccount(account_opt).unwrap();
    let address = test_session.get_receive_address(new_account);
    let sat = 1_040;
    let txid = test_session.node_sendtoaddress(&address.address, sat, None);
    test_session.wait_tx(vec![new_account], &txid, Some(sat), Some(TransactionType::Incoming));
    *balances.entry(new_account).or_insert(0) += sat;

    assert!(new_session.get_subaccount(new_account).is_err());
    new_session.discover_subaccounts(&credentials);
    new_session.get_subaccounts().unwrap();
    assert!(new_session.get_subaccount(new_account).is_ok());

    let btc_key = test_session.btc_key();

    for subaccount in subaccounts.iter() {
        new_session.wait_account_n_txs(subaccount.account_num, 1);

        let opt = GetBalanceOpt {
            subaccount: subaccount.account_num,
            num_confs: 0,
            confidential_utxos_only: None,
        };
        let balance = *new_session.get_balance(&opt).unwrap().get(&btc_key).unwrap_or(&0i64) as u64;
        assert_eq!(
            balance,
            *balances.get(&subaccount.account_num).unwrap(),
            "subaccount {} balance mismatch",
            subaccount.account_num
        );
    }

    // tx belong to the wallet
    assert!(test_session.session.get_transaction_hex(&txid).is_ok());
    assert!(test_session.session.get_transaction_details(&txid).is_ok());
    // tx does not belong to the wallet
    let fake_txid = "0000000000000000000000000000000000000000000000000000000000000000";
    assert!(test_session.session.get_transaction_hex(&fake_txid).is_err());
    assert!(test_session.session.get_transaction_details(&fake_txid).is_err());

    // Auth handler login does not have xprv, thus signing is disabled
    let tx = {
        let utxos = test_session.utxos(1);
        let asset = test_session.session.network.policy_asset.clone();
        let mut create_opt =
            test_session.create_opt(&address.address, 10000, asset, None, 1, utxos);
        test_session.session.create_transaction(&mut create_opt).unwrap()
    };
    assert!(matches!(new_session.sign_transaction(&tx), Err(Error::Generic(_))));

    new_session.disconnect().unwrap();
    test_session.stop();
}

#[test]
fn coinbase_bitcoin() {
    coinbase(false);
}

#[test]
fn coinbase_liquid() {
    coinbase(true);
}

fn coinbase(is_liquid: bool) {
    // Receive a coinbase transaction in the wallet
    let test_session = TestSession::new(is_liquid, |_| ());

    // Do a transaction so we have some fees to collect, note that this is necessary for Liquid
    // since new blocks do not generate new coins.
    test_session.node_sendtoaddress(&test_session.node_getnewaddress(None), 10000, None);

    // Generate a coinbase sending an output to the wallet.
    test_session.node_generatetoaddress(1, &test_session.get_receive_address(0).address);
    test_session.wait_blockheight(102);
    test_session.wait_account_n_txs(0, 1);
    assert!(test_session.balance_account(0, None, None) > 0);
    let txlist = test_session.get_tx_list(0);
    assert_eq!(txlist.len(), 1);
    assert_eq!(txlist[0].fee, 0);

    // This coin is immature though, coinbase outputs cannot be spent until 101 blocks.
}

#[test]
fn spend_unsynced_bitcoin() {
    spend_unsynced(false);
}

#[test]
fn spend_unsynced_liquid() {
    spend_unsynced(true);
}

fn spend_unsynced(is_liquid: bool) {
    let mut test_session = TestSession::new(is_liquid, |_| ());

    // Fund the wallet
    let sat1 = 10_000;
    let address1 = test_session.get_receive_address(0).address;
    let txid1 = test_session.node_sendtoaddress(&address1, sat1, None);
    test_session.wait_tx(vec![0], &txid1, Some(sat1), Some(TransactionType::Incoming));

    // Send a transcation, which will spend the only utxo we have.
    let sat2 = 1_000;
    let address2 = test_session.node_getnewaddress(None);
    let utxos = test_session.utxos(0);
    let mut create_opt = CreateTransaction::default();
    create_opt.addressees.push(AddressAmount {
        address: address2.to_string(),
        satoshi: sat2,
        asset_id: test_session.asset_id(),
    });
    create_opt.utxos = utils::convertutxos(&utxos);
    let tx = test_session.session.create_transaction(&mut create_opt).unwrap();
    let signed_tx = test_session.session.sign_transaction(&tx).unwrap();
    let fee = signed_tx.fee;
    let txid2 = test_session.session.broadcast_transaction(&signed_tx.hex).unwrap();

    // Attempt to create a new transaction before we received the transaction notification and
    // the db is updated with the sent transaction.
    let events = test_session.session.filter_events("transaction");
    assert!(events.iter().all(|e| e["transaction"]["txhash"].as_str().unwrap() != txid2));

    let btc_key = test_session.btc_key();
    let utxos = test_session.utxos(0);
    let utxos_btc = utxos.0.get(&btc_key).unwrap();
    assert_eq!(utxos_btc.len(), 1);
    assert!(utxos_btc.iter().any(|u| u.txhash == txid1));

    // We are reusing the utxo spend by txid2 and create tx fails.
    // If we allowed to broadcast this transaction we would get a
    // "bad-txns-inputs-missingorspent"
    let mut create_opt = CreateTransaction::default();
    create_opt.addressees.push(AddressAmount {
        address: address2.to_string(),
        satoshi: sat2,
        asset_id: test_session.asset_id(),
    });
    create_opt.utxos = utils::convertutxos(&utxos);
    let res = test_session.session.create_transaction(&mut create_opt);
    assert!(res.is_err()); // insufficient funds

    // No notification yet
    let events = test_session.session.filter_events("transaction");
    assert!(events.iter().all(|e| e["transaction"]["txhash"].as_str().unwrap() != txid2));

    // Now wait for notification
    test_session.wait_tx(vec![0], &txid2, Some(sat2 + fee), Some(TransactionType::Outgoing));

    // Now that the db is synced, the utxo spent by txid2 is not included
    let utxos = test_session.utxos(0);
    let utxos_btc = utxos.0.get(&btc_key).unwrap();
    assert_eq!(utxos_btc.len(), 1);
    assert!(utxos_btc.iter().all(|u| u.txhash != txid1));
}

#[test]
fn addresses_bitcoin() {
    addresses(false);
}

#[test]
fn addresses_liquid() {
    addresses(true);
}

fn addresses(is_liquid: bool) {
    let mut test_session = TestSession::new(is_liquid, |_| ());

    // We send some coins to each address to ensure a new address is generated.
    let sat = 1000;
    for i in 1..12 {
        let ap = test_session.get_receive_address(0);
        assert_eq!(ap.pointer, i);
        let txid = test_session.node_sendtoaddress(&ap.address, sat, None);
        test_session.wait_tx(vec![0], &txid, Some(sat), Some(TransactionType::Incoming));
    }

    // last_pointer None returns the newest generated addresses
    let mut opt = GetPreviousAddressesOpt {
        subaccount: 0,
        last_pointer: None,
        is_internal: false,
        count: 10,
    };

    let previous_addresses = test_session.session.get_previous_addresses(&opt).unwrap();
    assert_eq!(previous_addresses.list.len(), 10);
    assert_eq!(previous_addresses.list[0].pointer, 11);
    assert_eq!(previous_addresses.list[0].tx_count, 1);
    assert_eq!(previous_addresses.list[9].pointer, 2);
    assert_eq!(previous_addresses.last_pointer, Some(2));
    assert!(previous_addresses.list.iter().all(|e| !e.is_internal));

    if is_liquid {
        assert!(previous_addresses.list.iter().all(|e| e.is_confidential.unwrap()));
    }

    opt.last_pointer = Some(100);
    let previous_addresses_100 = test_session.session.get_previous_addresses(&opt).unwrap();
    opt.last_pointer = Some(12);
    let previous_addresses_12 = test_session.session.get_previous_addresses(&opt).unwrap();
    assert_eq!(previous_addresses, previous_addresses_100);
    assert_eq!(previous_addresses, previous_addresses_12);

    opt.last_pointer = previous_addresses.last_pointer;
    let previous_addresses = test_session.session.get_previous_addresses(&opt).unwrap();
    assert_eq!(previous_addresses.list.len(), 2);
    assert_eq!(previous_addresses.list[0].pointer, 1);
    assert_eq!(previous_addresses.list[1].pointer, 0);
    assert_eq!(previous_addresses.last_pointer, None);

    opt.is_internal = true;
    let previous_addresses_int = test_session.session.get_previous_addresses(&opt).unwrap();
    assert!(previous_addresses_int.list.iter().all(|e| e.is_internal));
    assert_eq!(previous_addresses_int.list.len(), 1);
    assert_eq!(previous_addresses_int.list[0].pointer, 0);
    assert_eq!(previous_addresses_int.last_pointer, None);

    // Create a new account
    let opt = CreateAccountOpt {
        name: "p2sh-p2wpkh-2".into(),
        subaccount: 16,
        ..Default::default()
    };
    test_session.session.create_subaccount(opt).unwrap();
    let opt = GetPreviousAddressesOpt {
        subaccount: 16,
        last_pointer: None,
        is_internal: false,
        count: 10,
    };

    let previous_addresses = test_session.session.get_previous_addresses(&opt).unwrap();
    assert_eq!(previous_addresses.list.len(), 1);
    assert_eq!(previous_addresses_int.list[0].pointer, 0);
    assert_eq!(previous_addresses_int.last_pointer, None);
}

#[test]
fn sighash_bitcoin() {
    sighash(false);
}

#[test]
fn sighash_liquid() {
    sighash(true);
}

fn sighash(is_liquid: bool) {
    let mut test_session = TestSession::new(is_liquid, |_| ());

    let sat = 10000;
    let txid =
        test_session.node_sendtoaddress(&test_session.get_receive_address(0).address, sat, None);
    test_session.wait_tx(vec![0], &txid, Some(sat), Some(TransactionType::Incoming));

    let sighashes = [
        0x01, // SIGHASH_ALL
        0x02, // SIGHASH_NONE
        0x03, // SIGHASH_SINGLE
        0x81, // SIGHASH_ALL | SIGHASH_ANYONECANPAY
        0x82, // SIGHASH_NONE | SIGHASH_ANYONECANPAY
        0x83, // SIGHASH_SINGLE | SIGHASH_ANYONECANPAY
    ];
    let mut allowed_sighashes = vec![0x01];
    if is_liquid {
        allowed_sighashes.push(0x83);
    }
    for sighash in sighashes {
        // Create transaction for replacement
        let mut create_opt = CreateTransaction::default();
        let dest_address = test_session.get_receive_address(0).address;
        create_opt.subaccount = 0;
        create_opt.addressees.push(AddressAmount {
            address: dest_address,
            satoshi: 5000,
            asset_id: test_session.asset_id(),
        });
        create_opt.utxos = utils::convertutxos(&test_session.utxos(create_opt.subaccount));
        let mut txc = test_session.session.create_transaction(&mut create_opt).unwrap();
        if is_liquid {
            // SIGHASH_RANGEPROOF is not supported yet upstream
            let sighash_rangeproof = 0x40;
            for u in txc.used_utxos.iter_mut() {
                u.sighash = Some(sighash | sighash_rangeproof);
            }
            assert!(test_session.session.sign_transaction(&txc).is_err());
        }
        for u in txc.used_utxos.iter_mut() {
            u.sighash = Some(sighash);
        }
        let res = test_session.session.sign_transaction(&txc);
        if !allowed_sighashes.contains(&sighash) {
            assert!(res.is_err());
            continue;
        }
        let txs = res.unwrap();
        let tx_decoded = test_session
            .node
            .client
            .call::<Value>("decoderawtransaction", &[txs.hex.clone().into()])
            .unwrap();
        for inp in tx_decoded["vin"].as_array().unwrap().iter() {
            let sig = inp["txinwitness"].as_array().unwrap()[0].as_str().unwrap();
            let sighash_hex = &sig[sig.len() - 2..];
            assert_eq!(sighash_hex, format!("{:01$x}", sighash, 2));
        }

        // Broadcast the tx and get it from the tx list to verify the signature
        let txid = test_session.session.broadcast_transaction(&txs.hex).unwrap();
        test_session.wait_tx(vec![0], &txid, Some(txs.fee), Some(TransactionType::Redeposit));
        test_session.get_tx_from_list(0, &txid);
    }
}

#[test]
fn skip_signing_bitcoin() {
    skip_signing(false);
}

#[test]
fn skip_signing_liquid() {
    skip_signing(true);
}

fn skip_signing(is_liquid: bool) {
    let mut test_session = TestSession::new(is_liquid, |_| ());

    let sat = 10000;
    let txid1 =
        test_session.node_sendtoaddress(&test_session.get_receive_address(0).address, sat, None);
    let txid2 =
        test_session.node_sendtoaddress(&test_session.get_receive_address(0).address, sat, None);
    test_session.wait_tx(vec![0], &txid1, Some(sat), Some(TransactionType::Incoming));
    test_session.wait_tx(vec![0], &txid2, Some(sat), Some(TransactionType::Incoming));

    let mut create_opt = CreateTransaction::default();
    let dest_address = test_session.get_receive_address(0).address;
    create_opt.subaccount = 0;
    create_opt.addressees.push(AddressAmount {
        address: dest_address,
        satoshi: 15000,
        asset_id: test_session.asset_id(),
    });
    create_opt.utxos = utils::convertutxos(&test_session.utxos(create_opt.subaccount));
    let mut txc = test_session.session.create_transaction(&mut create_opt).unwrap();
    // sign the 2nd input
    txc.used_utxos[0].skip_signing = true;
    let mut txs1 = test_session.session.sign_transaction(&txc).unwrap();
    // sign the all inputs
    txs1.used_utxos[0].skip_signing = false;
    let txs2 = test_session.session.sign_transaction(&txs1).unwrap();

    // Broadcast the tx and get it from the tx list to verify the signature
    let txid = test_session.session.broadcast_transaction(&txs2.hex).unwrap();
    test_session.wait_tx(vec![0], &txid, Some(txs2.fee), Some(TransactionType::Redeposit));
    test_session.get_tx_from_list(0, &txid);

    let txc_decoded = test_session
        .node
        .client
        .call::<Value>("decoderawtransaction", &[txc.hex.clone().into()])
        .unwrap();
    let txc_vin_decoded = txc_decoded["vin"].as_array().unwrap();
    let txs1_decoded = test_session
        .node
        .client
        .call::<Value>("decoderawtransaction", &[txs1.hex.clone().into()])
        .unwrap();
    let txs1_vin_decoded = txs1_decoded["vin"].as_array().unwrap();
    let txs2_decoded = test_session
        .node
        .client
        .call::<Value>("decoderawtransaction", &[txs2.hex.clone().into()])
        .unwrap();
    let txs2_vin_decoded = txs2_decoded["vin"].as_array().unwrap();

    assert!(txc_vin_decoded[0] == txs1_vin_decoded[0]);
    assert!(txc_vin_decoded[1] != txs1_vin_decoded[1]);
    assert!(txc_vin_decoded[0] != txs2_vin_decoded[0]);
    assert!(txc_vin_decoded[1] != txs2_vin_decoded[1]);
    assert!(txs1_vin_decoded[1] == txs2_vin_decoded[1]);
}

#[test]
fn not_unblindable_liquid() {
    let test_session = TestSession::new(true, |_| ());

    // Receive a utxos that is not unblindable by the wallet
    let ap = test_session.get_receive_address(0);
    let address = utils::to_not_unblindable(&ap.address);
    let sat = 10_000;
    let txid = test_session.node_sendtoaddress(&address, sat, None);
    test_session.wait_tx(vec![0], &txid, None, None);

    // Balance is empty and there are no utxos
    assert_eq!(0, test_session.balance_account(0, None, None));
    assert!(test_session.utxos(0).0.is_empty());
}

#[test]
fn labels() {
    // Create a session and two accounts
    let mut test_session = TestSession::new(false, |_| ());
    let account1 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            name: "Account 1".into(),
            subaccount: 1,
            ..Default::default() // p2wpkh
        })
        .unwrap();
    let account2 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            name: "Account 2".into(),
            subaccount: 2,
            ..Default::default() // p2pkh
        })
        .unwrap();

    // Fund account #1
    let sat = 9876543;
    let acc1_address = test_session.get_receive_address(account1.account_num);
    let txid = test_session.node_sendtoaddress(&acc1_address.address, sat, None);
    test_session.wait_tx(
        vec![account1.account_num],
        &txid,
        Some(sat),
        Some(TransactionType::Incoming),
    );

    // Send from account #1 to account #2 with a memo
    let mut create_opt = CreateTransaction::default();
    create_opt.subaccount = account1.account_num;
    let sat = 50000;
    create_opt.addressees.push(AddressAmount {
        address: test_session.get_receive_address(account2.account_num).address,
        satoshi: sat,
        asset_id: None,
    });
    create_opt.utxos = utils::convertutxos(&test_session.utxos(create_opt.subaccount));
    create_opt.memo = Some("Foo, Bar Foo".into());
    let tx = test_session.session.create_transaction(&mut create_opt).unwrap();
    let signed_tx = test_session.session.sign_transaction(&tx).unwrap();
    let txid = test_session.session.broadcast_transaction(&signed_tx.hex).unwrap();
    test_session.wait_tx(
        vec![account1.account_num, account2.account_num],
        &txid,
        Some(sat + signed_tx.fee),
        Some(TransactionType::Outgoing),
    );

    // Memos should be set across all accounts
    assert_eq!(test_session.get_tx_from_list(account1.account_num, &txid).memo, "Foo, Bar Foo");
    assert_eq!(test_session.get_tx_from_list(account2.account_num, &txid).memo, "Foo, Bar Foo");

    test_session.session.set_transaction_memo(&txid, "Bar, Foo Qux").unwrap();
    assert_eq!(test_session.get_tx_from_list(account1.account_num, &txid).memo, "Bar, Foo Qux");
    assert_eq!(test_session.get_tx_from_list(account2.account_num, &txid).memo, "Bar, Foo Qux");

    // Using the external signer and broadcast_transaction does not the memo
    let test_signer = test_session.test_signer();
    let mut create_opt = CreateTransaction::default();
    create_opt.subaccount = account1.account_num;
    let sat = 50000;
    create_opt.addressees.push(AddressAmount {
        address: test_session.get_receive_address(account2.account_num).address,
        satoshi: sat,
        asset_id: None,
    });
    create_opt.utxos = utils::convertutxos(&test_session.utxos(create_opt.subaccount));
    create_opt.memo = Some("Foo, Bar Foo".into());
    let tx = test_session.session.create_transaction(&mut create_opt).unwrap();
    let signed_tx = test_signer.sign_tx(&tx);
    let txid = test_session.session.broadcast_transaction(&signed_tx.hex).unwrap();
    test_session.wait_tx(
        vec![account1.account_num, account2.account_num],
        &txid,
        Some(sat + signed_tx.fee),
        Some(TransactionType::Outgoing),
    );

    // Memos is not set across all accounts
    assert_eq!(test_session.get_tx_from_list(account1.account_num, &txid).memo, "");
    assert_eq!(test_session.get_tx_from_list(account2.account_num, &txid).memo, "");

    test_session.stop();
}

#[test]
fn rbf() {
    // Create session/account and fund id
    let mut test_session = TestSession::new(false, |_| ());
    test_session
        .session
        .create_subaccount(CreateAccountOpt {
            name: "Account 1".into(),
            subaccount: 1,
            ..Default::default()
        })
        .unwrap();
    let sat = 9876543;
    let txid =
        test_session.node_sendtoaddress(&test_session.get_receive_address(1).address, sat, None);
    test_session.wait_tx(vec![1], &txid, Some(sat), Some(TransactionType::Incoming));

    // Create transaction for replacement
    let mut create_opt = CreateTransaction::default();
    let dest_address = test_session.get_receive_address(1).address;
    create_opt.subaccount = 1;
    create_opt.addressees.push(AddressAmount {
        address: dest_address,
        satoshi: 50000,
        asset_id: None,
    });
    create_opt.utxos = utils::convertutxos(&test_session.utxos(create_opt.subaccount));
    create_opt.fee_rate = Some(25000);
    create_opt.memo = Some("poz qux".into());
    let tx = test_session.session.create_transaction(&mut create_opt).unwrap();
    let signed_tx = test_session.session.sign_transaction(&tx).unwrap();
    let txid1 = test_session.session.broadcast_transaction(&signed_tx.hex).unwrap();
    test_session.wait_tx(vec![1], &txid1, Some(signed_tx.fee), Some(TransactionType::Redeposit));
    let txitem = test_session.get_tx_from_list(1, &txid1);
    assert!(test_session.utxos(1).0.get("btc").unwrap().iter().any(|e| e.txhash == txid1));
    assert_eq!(test_session.balance_account(1, None, None), sat - txitem.fee);

    assert_eq!(txitem.fee_rate / 1000, 25);

    // Replace it
    let mut create_opt = CreateTransaction::default();
    create_opt.subaccount = 1;
    create_opt.previous_transaction = Some(txitem);
    create_opt.fee_rate = Some(43000);
    let tx = test_session.session.create_transaction(&mut create_opt).unwrap();
    let signed_tx = test_session.session.sign_transaction(&tx).unwrap();
    let txid2 = test_session.session.broadcast_transaction(&signed_tx.hex).unwrap();
    test_session.wait_tx(vec![1], &txid2, Some(signed_tx.fee), Some(TransactionType::Redeposit));
    let txitem = test_session.get_tx_from_list(1, &txid2);
    assert_eq!(txitem.fee_rate / 1000, 43);
    assert_eq!(txitem.memo, "poz qux");

    // The old transaction should be gone (after the next sync with the server)
    for i in 0..60 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if test_session.get_tx_list(1).iter().all(|e| e.txhash != txid1) {
            assert!(test_session.utxos(1).0.get("btc").unwrap().iter().all(|e| e.txhash != txid1));
            assert_eq!(test_session.balance_account(1, None, None), sat - txitem.fee);
            break;
        }
        assert!(i < 59, "timeout waiting for replaced transaction to disappear");
    }

    // Transactions that are not properly signed should be rejected, to prevent the user from
    // being tricked into fee-bumping them.
    let mut tx =
        test_session.electrs.client.transaction_get(&txitem.txhash.parse().unwrap()).unwrap();
    let mut witness_vec = tx.input[0].witness.to_vec();
    witness_vec[0][5] = witness_vec[0][5].wrapping_add(1);
    tx.input[0].witness = Witness::from_vec(witness_vec);
    let tx = BETransaction::Bitcoin(tx);

    let account = test_session.session.get_account(1).unwrap();
    let is_valid = account.verify_own_txs(&[(tx.txid(), tx)]).unwrap();
    assert_eq!(is_valid, false);

    test_session.stop();
}

#[test]
fn test_electrum_disconnect() {
    let mut test_session = TestSession::new(false, |_| ());
    assert!(test_session.electrs.client.ping().is_ok());

    assert_eq!(test_session.session.filter_events("network").len(), 1);
    test_session.electrs.kill().unwrap();
    for i in 0.. {
        assert!(i < 100);
        if test_session.session.filter_events("network").len() > 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    assert_eq!(
        test_session.session.filter_events("network").last(),
        Some(&utils::ntf_network(State::Disconnected, State::Connected))
    );
    assert_eq!(test_session.session.filter_events("network").len(), 2);

    test_session.session.disconnect().unwrap();

    assert_eq!(
        test_session.session.filter_events("network").last(),
        Some(&utils::ntf_network(State::Disconnected, State::Disconnected))
    );
    assert_eq!(test_session.session.filter_events("network").len(), 3);

    // Attempt to connect but Electrs is still down
    test_session.session.connect(&Value::Null).unwrap();

    assert_eq!(
        test_session.session.filter_events("network").last(),
        Some(&utils::ntf_network(State::Disconnected, State::Connected))
    );
    assert_eq!(test_session.session.filter_events("network").len(), 4);

    // Attempt to connect with another session but Electrs is still down
    let mut new_session = {
        let network = test_session.network_parameters().clone();
        ElectrumSession::new(network).unwrap()
    };
    new_session.connect(&Value::Null).unwrap();

    assert_eq!(
        new_session.filter_events("network").last(),
        Some(&utils::ntf_network(State::Disconnected, State::Connected))
    );
    assert_eq!(new_session.filter_events("network").len(), 1);

    // Disconnect without having called login
    new_session.disconnect().unwrap();
    assert_eq!(new_session.filter_events("network").len(), 2);
    assert_eq!(
        new_session.filter_events("network").last(),
        Some(&utils::ntf_network(State::Disconnected, State::Disconnected))
    );
}

// Test the low-level spv_cross_validate()
#[test]
fn spv_cross_validate() {
    // Scenario 1: our local chain is a minority fork
    {
        // Setup two competing chain forks at height 126 and 1142
        let (mut test_session1, mut test_session2) = setup_forking_sessions(false);
        test_session1.node_generate(5); // session1 is on a minority fork
        test_session2.node_generate(1020); // session2 is on the most-work chain
        test_session1.wait_blockheight(126);
        test_session2.wait_blockheight(1141);

        // Grab direct access to session1's HeadersChain
        let session1_chain = get_chain(&mut test_session1);
        assert_eq!(session1_chain.height(), 126);

        // Cross-validate session1's chain against session'2 electrum server
        let session2_electrum_url =
            ElectrumUrl::Plaintext(test_session2.electrs.electrum_url.clone());
        let result = spv::spv_cross_validate(
            &session1_chain,
            &session1_chain.tip().block_hash(),
            &session2_electrum_url,
            None,
            &None,
        )
        .unwrap();

        let inv = assert_unwrap_invalid(result);
        assert_eq!(inv.common_ancestor, 121);
        assert_eq!(inv.longest_height, 1141);

        test_session2.stop();
    }

    // Scenario 2: our local chain is lagging behind a longer chain
    {
        // Setup two nodes, make session2 ahead by 12 blocks
        let (mut test_session1, mut test_session2) = setup_forking_sessions(false);
        test_session2.node_generate(12);
        test_session2.wait_blockheight(133);

        // Grab direct access to session1's HeadersChain
        let session1_chain = get_chain(&mut test_session1);
        assert_eq!(session1_chain.height(), 121);

        // Cross-validate session1's chain against session'2 electrum server
        let session2_electrum_url =
            ElectrumUrl::Plaintext(test_session2.electrs.electrum_url.clone());
        let result = spv::spv_cross_validate(
            &session1_chain,
            &session1_chain.tip().block_hash(),
            &session2_electrum_url,
            None,
            &None,
        )
        .unwrap();

        assert_eq!(assert_unwrap_invalid(result).longest_height, 133);

        test_session2.stop();
    }
}

// Test high-level session management, background validation and transaction status
#[test]
fn spv_cross_validation_session() {
    let (mut test_session1, mut test_session2) = setup_forking_sessions(true);

    // Send a payment to session1
    let sat = 999999;
    let ap = test_session1.get_receive_address(0);
    let txid = test_session1.node_sendtoaddress(&ap.address, sat, None);
    test_session1.wait_tx(vec![0], &txid, Some(sat), Some(TransactionType::Incoming));
    let txitem = test_session1.get_tx_from_list(0, &txid);
    assert_eq!(txitem.block_height, 0);
    assert_eq!(txitem.spv_verified, "unconfirmed");
    info!("sent mempool tx");

    // Confirm it, wait for it to SPV-validate
    test_session1.node_generate(1);
    test_session1.wait_blockheight(122);
    test_session1.wait_tx_spv_change(&txid, "verified");
    assert_eq!(test_session1.get_tx_from_list(0, &txid).block_height, 122);
    info!("tx confirmed and spv validated");

    // Extend session2, putting session1 on a minority fork
    test_session2.node_generate(10);
    test_session2.wait_blockheight(131);
    test_session1.wait_blockheight(122);
    let cross_result = test_session1.wait_spv_cross_validation_change(false);
    let inv = assert_unwrap_invalid(cross_result);
    assert_eq!(inv.common_ancestor, 121);
    assert_eq!(inv.longest_height, 131);
    assert_eq!(test_session1.get_tx_from_list(0, &txid).spv_verified, "not_longest");
    info!("extended session2, making session1 the minority");

    // Extend session1, making it the best chain
    test_session1.node_generate(11);
    test_session1.wait_blockheight(133);
    let cross_result = test_session1.wait_spv_cross_validation_change(true);
    assert!(cross_result.is_valid());
    assert_eq!(test_session1.get_tx_from_list(0, &txid).spv_verified, "verified");
    assert_eq!(test_session1.session.block_status().unwrap().0, 133);
    info!("extended session1, making session1 the majority");

    // Make session1 the minority again
    test_session2.node_generate(3);
    let cross_result = test_session1.wait_spv_cross_validation_change(false);
    let inv = assert_unwrap_invalid(cross_result);
    assert_eq!(inv.common_ancestor, 121);
    assert_eq!(inv.longest_height, 134);
    assert_eq!(test_session1.get_tx_from_list(0, &txid).spv_verified, "not_longest");
    info!("extended session2, making session1 the minority (again)");

    // Reorg session1 into session2, pointing both to the same longest chain
    // Cross-validation should now succeed, but our tx should now appear as unconfirmed again
    test_session1.node_connect(test_session2.p2p_port);
    let cross_result = test_session1.wait_spv_cross_validation_change(true);
    assert!(cross_result.is_valid());
    let txitem = test_session1.get_tx_from_list(0, &txid);
    assert_eq!(txitem.block_height, 0);
    assert_eq!(txitem.spv_verified, "unconfirmed");
    info!("reorged session1 into session2, tx is unconfirmed again");

    // Re-confirm the tx and then re-fork the chain, such that the tx is confirmed before the forking point
    // Cross-validation should fail, but the tx should still appear as SPV-validated
    test_session1.node_generate(1);
    test_session1.wait_tx_spv_change(&txid, "verified");
    assert_eq!(test_session1.get_tx_from_list(0, &txid).block_height, 135);
    test_session1.node_disconnect_all();
    test_session1.node_generate(5);
    test_session2.node_generate(10);
    let cross_result = test_session1.wait_spv_cross_validation_change(false);
    let inv = assert_unwrap_invalid(cross_result);
    assert_eq!(inv.common_ancestor, 135);
    assert_eq!(inv.longest_height, 145);
    let txitem = test_session1.get_tx_from_list(0, &txid);
    assert_eq!(txitem.block_height, 135);
    assert_eq!(txitem.spv_verified, "verified");

    test_session1.stop();
    test_session2.stop();
}

#[test]
fn test_spv_timeout() {
    let _ = env_logger::try_init();

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap(); // 0 means the OS choose a free port
    let mut network = NetworkParameters::default();
    let tempdir = TempDir::new().unwrap();
    let tempdir = format!("{}", tempdir.path().display());
    network.state_dir = tempdir;
    network.electrum_url = Some(format!("{}", listener.local_addr().unwrap()));
    let (s, r) = std::sync::mpsc::channel();
    thread::spawn(move || {
        // emulate an electrum server socket not replying for 30 seconds
        s.send(()).unwrap();
        let (_, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(30));
    });
    // ensure the above thread is started and accepting connections
    r.recv_timeout(Duration::from_secs(1)).unwrap();

    let now = Instant::now();
    let param_download = SPVDownloadHeadersParams {
        params: SPVCommonParams {
            network,
            timeout: Some(1),
            encryption_key: None,
        },
        headers_to_download: Some(1),
    };
    let _ = headers::download_headers(&param_download);

    assert!(now.elapsed().as_secs() <= 5, "more than timeout time passed");
}

#[test]
#[ignore] // launch `cargo test -- test_tor --include-ignored` with a running tor session on 127.0.0.1:9050
fn test_tor() {
    let _ = env_logger::try_init();

    let state_dir = TempDir::new().unwrap();
    let state_dir_str = format!("{}", state_dir.path().display());

    let mut network = NetworkParameters::default();
    network.mainnet = true;
    network.state_dir = state_dir_str;
    assert_eq!(network.id(), NetworkId::Bitcoin(bitcoin::Network::Bitcoin));
    // blockstream mainnet server, we can't use localhost because it's not reachable via tor
    network.electrum_onion_url =
        Some("explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion:110".to_string());
    network.use_tor = Some(true);
    network.set_asset_registry_onion_url(
        "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion".to_string(),
    );
    network.policy_asset =
        Some("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d".to_string());
    network.proxy = Some("127.0.0.1:9050".into());
    network.spv_enabled = Some(false);

    info!("creating gdk session");
    let mut session = ElectrumSession::new(network.clone()).unwrap();
    session.connect(&serde_json::to_value(&network).unwrap()).unwrap();

    let credentials = Credentials {
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        bip39_passphrase: "".to_string(),
    };
    session.auth_handler_login(&credentials);

    assert_eq!(session.get_fee_estimates().unwrap().len(), 25);

    let params = SPVDownloadHeadersParams {
        params: SPVCommonParams {
            network,
            timeout: None,
            encryption_key: None,
        },
        headers_to_download: Some(1),
    };
    let result = headers::download_headers(&params).unwrap();
    assert_eq!(result.height, 1);
}

#[test]
fn test_spv_over_period() {
    // regtest doesn't retarget after a period (2016 blocks)
    let mut test_session = TestSession::new(false, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));
    test_session.fund(100_000_000, None);

    let initial_block = 101;
    let block_to_mine = 200;
    let times = 10;

    for i in 1..(times + 1) {
        // generating all blocks at once may cause rpc timeout
        test_session.node_generate(block_to_mine);
        test_session.wait_blockheight(initial_block + i * block_to_mine);
    }

    let txid = test_session.send_tx(
        &node_address,
        10_000,
        None,
        Some(MEMO1.to_string()),
        None,
        None,
        None,
    ); // p2shwpkh
    test_session.mine_block();

    test_session.spv_verify_tx(&txid, initial_block + block_to_mine * times + 1, Some(100));
}

#[test]
fn test_spv_external_concurrent_spv_enabled() {
    test_spv_external_concurrent(true);
}

#[test]
fn test_spv_external_concurrent_spv_disabled() {
    test_spv_external_concurrent(false);
}

fn test_spv_external_concurrent(spv_enabled: bool) {
    let mut test_session = TestSession::new(false, |n| n.spv_enabled = Some(spv_enabled));
    // network.state_dir = "."; // launching twice with the same dir would break the test, because the regtest blockchain is different

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));
    test_session.fund(100_000_000, None);

    let initial_block = 101u32;

    let mut txids = vec![];
    for _ in 0..10u32 {
        let txid = test_session.send_tx(
            &node_address,
            10_000,
            None,
            Some(MEMO1.to_string()),
            None,
            None,
            None,
        ); // p2shwpkh
        test_session.mine_block();

        txids.push(txid);
    }

    let mut handles = vec![];
    for (i, txid) in txids.into_iter().enumerate() {
        let tip = test_session.electrs_tip() as u32;
        let network = test_session.network.clone();
        test_session.node_generate(1); // doesn't wait the sync, may trigger header download anywhere

        handles.push(thread::spawn(move || {
            utils::spv_verify_tx(network, tip, &txid, initial_block + i as u32 + 1, Some(10));
        }));
    }

    while let Some(h) = handles.pop() {
        h.join().unwrap();
    }
}

#[test]
fn test_utxo_unconfirmed() {
    let test_session = TestSession::new(false, |_| ());
    let address = test_session.get_receive_address(0).address;
    let initial_height = test_session.node_get_block_count();

    for i in 1..10 {
        let txid = test_session.node_sendtoaddress(&address, 100_000, None);
        test_session.node_generate(1);
        test_session.wait_block_ntf(initial_height + i);
        let utxos = test_session.utxos(0);
        assert!(utxos.0.get("btc").unwrap().iter().any(|u| u.txhash == txid));
    }
}

fn setup_forking_sessions(enable_session_cross: bool) -> (TestSession, TestSession) {
    let test_session2 = TestSession::new(false, |_| ());

    let test_session1 = TestSession::new(false, |network| {
        if enable_session_cross {
            network.spv_multi = Some(true);
            network.spv_servers = Some(vec![test_session2.electrs.electrum_url.clone()]);
        }
    });

    // Connect nodes and point both to the same tip
    test_session2.node_connect(test_session1.p2p_port);
    test_session1.node_generate(20);

    test_session1.wait_blockheight(121);
    test_session2.wait_blockheight(121);

    // Disconnect so they don't learn about eachother blocks
    test_session1.node_disconnect_all();

    (test_session1, test_session2)
}

fn get_chain(test_session: &mut TestSession) -> HeadersChain {
    test_session.stop();
    HeadersChain::new(&test_session.session.network.state_dir, bitcoin::Network::Regtest).unwrap()
}

fn assert_unwrap_invalid(result: spv::CrossValidationResult) -> spv::CrossValidationInvalid {
    match result {
        spv::CrossValidationResult::Invalid(inv) => inv,
        _ => panic!("expected cross-validation to fail"),
    }
}
