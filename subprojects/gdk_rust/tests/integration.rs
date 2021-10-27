use electrum_client::ElectrumApi;
use gdk_common::be::BETransaction;
use gdk_common::model::{
    AddressAmount, CreateAccountOpt, CreateTransaction, GetBalanceOpt, GetNextAccountOpt,
    GetUnspentOutputs, RenameAccountOpt, SPVVerifyResult, UpdateAccountOpt, UtxoStrategy,
};
use gdk_common::scripts::ScriptType;
use gdk_common::session::Session;
use gdk_common::Network;
use gdk_electrum::error::Error;
use gdk_electrum::headers::bitcoin::HeadersChain;
use gdk_electrum::interface::ElectrumUrl;
use gdk_electrum::{determine_electrum_url_from_net, spv, ElectrumSession};

use log::info;
use std::collections::HashMap;
use std::{env, path};
use tempdir::TempDir;

mod test_session;
use test_session::TestSession;

static MEMO1: &str = "hello memo";
static MEMO2: &str = "hello memo2";

#[test]
fn roundtrip_bitcoin() {
    let mut test_session = setup_session(false, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));
    let node_bech32_address = test_session.node_getnewaddress(Some("bech32"));
    let node_legacy_address = test_session.node_getnewaddress(Some("legacy"));
    test_session.fund(100_000_000, None);
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
    test_session.test_set_get_memo(&txid, MEMO1, MEMO2);
    test_session.is_verified(&txid, SPVVerifyResult::Unconfirmed);
    test_session.send_tx(&node_bech32_address, 10_000, None, None, None, None, None); // p2wpkh
    test_session.send_tx(&node_legacy_address, 10_000, None, None, None, None, None); // p2pkh
    test_session.send_all(&node_legacy_address, None);
    test_session.mine_block();
    test_session.send_tx_same_script();
    test_session.fund(100_000_000, None);
    test_session.send_multi(3, 100_000, &vec![]);
    test_session.send_multi(30, 100_000, &vec![]);
    test_session.mine_block();
    test_session.fees();
    test_session.settings();
    test_session.is_verified(&txid, SPVVerifyResult::Verified);
    test_session.reconnect();
    test_session.spv_verify_tx(&txid, 102);
    test_session.test_set_get_memo(&txid, MEMO2, ""); // after reconnect memo has been reloaded from disk
    let mut utxos = test_session.utxo("btc", vec![149739, 96697483]);
    test_session.check_decryption(103, &[&txid]);

    utxos.0.get_mut("btc").unwrap().retain(|e| e.satoshi == 149739); // we want to use the smallest utxo
    test_session.send_tx(&node_legacy_address, 10_000, None, None, Some(utxos), None, None);
    test_session.utxo("btc", vec![139569, 96697483]); // the smallest utxo has been spent
                                                      // TODO add a test with external UTXO

    test_session.stop();
}

#[test]
fn roundtrip_liquid() {
    let mut test_session = setup_session(true, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));
    let node_bech32_address = test_session.node_getnewaddress(Some("bech32"));
    let node_legacy_address = test_session.node_getnewaddress(Some("legacy"));

    let assets = test_session.fund(100_000_000, Some(1));
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
    test_session.check_decryption(101, &[&txid]);
    test_session.test_set_get_memo(&txid, MEMO1, MEMO2);
    test_session.is_verified(&txid, SPVVerifyResult::Unconfirmed);
    test_session.send_tx(&node_bech32_address, 10_000, None, None, None, None, None);
    test_session.send_tx(&node_legacy_address, 10_000, None, None, None, None, None);
    test_session.send_tx(&node_address, 10_000, Some(assets[0].clone()), None, None, None, None);
    test_session.send_tx(&node_address, 100, Some(assets[0].clone()), None, None, None, None); // asset should send below dust limit
    test_session.send_all(&node_address, Some(assets[0].to_string()));
    test_session.send_all(&node_address, test_session.asset_id());
    test_session.mine_block();
    let assets = test_session.fund(100_000_000, Some(3));
    test_session.send_multi(3, 100_000, &vec![]);
    test_session.send_multi(30, 100_000, &assets);
    test_session.mine_block();
    test_session.fees();
    test_session.settings();
    test_session.is_verified(&txid, SPVVerifyResult::Verified);
    test_session.reconnect();
    test_session.spv_verify_tx(&txid, 102);
    test_session.test_set_get_memo(&txid, MEMO2, "");
    test_session.utxo(&assets[0], vec![99000000]);

    test_session.fund(1_000_000, None);
    let mut utxos = test_session.utxo(
        "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
        vec![99651973, 1_000_000],
    );
    utxos
        .0
        .get_mut("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
        .unwrap()
        .retain(|e| e.satoshi == 1_000_000); // we want to use the smallest utxo
    test_session.send_tx(&node_legacy_address, 10_000, None, None, Some(utxos), None, None);
    test_session.utxo(
        "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
        vec![989740, 99651973],
    ); // the smallest utxo has been spent

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
    let mut test_session = setup_session(is_liquid, |_| ());

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
    assert!(create_opt.utxos.0.iter().all(|(_, v)| v.len() == 0));
    assert!(matches!(
        test_session.session.create_transaction(&mut create_opt),
        Err(Error::InsufficientFunds)
    ));

    // Not enough to pay the fee
    let wallet_sat = 5000;
    let wallet_address = test_session.get_receive_address(0).address;
    let txid = test_session.node_sendtoaddress(&wallet_address, wallet_sat, None);
    test_session.wait_account_tx(0, &txid);
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
        Err(Error::FeeRateBelowMinimum)
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
        "el1pq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfsxguu9nk3cxy6"
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

    // FIXME: add liquid taproot support
    if is_liquid {
        assert!(matches!(
            test_session.session.create_transaction(&mut create_opt),
            Err(Error::InvalidAddress)
        ));
    } else {
        test_session.session.create_transaction(&mut create_opt).unwrap();
    }

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

    // Unblinded
    if is_liquid {
        let unconf_addr = test_session::to_unconfidential(&addr);
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
    let mut test_session = setup_session(is_liquid, |_| ());

    // Fund the wallet with 2 coins
    let sat1 = 10_000;
    let addr1 = test_session.get_receive_address(0).address;
    let txid1 = test_session.node_sendtoaddress(&addr1, sat1, None);
    test_session.wait_account_tx(0, &txid1);
    test_session.mine_block();
    let sat2 = 20_000;
    let addr2 = test_session.get_receive_address(0).address;
    let txid2 = test_session.node_sendtoaddress(&addr2, sat2, None);
    test_session.wait_account_tx(0, &txid2);
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
    test_session.wait_account_tx(0, &txid);
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
    create_opt.utxos = GetUnspentOutputs::default();
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
        test_session.wait_account_tx(0, &txid);
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
        create_opt.utxos = utxos.clone();
        create_opt.utxo_strategy = UtxoStrategy::Manual;
        assert!(matches!(
            test_session.session.create_transaction(&mut create_opt),
            Err(Error::InsufficientFunds)
        ));

        // send_all with asset does not send all l-btc
        let utxos = test_session.utxo(&asset_a, vec![sat1_a]);
        let node_address = test_session.node_getnewaddress(None);
        let txid = test_session.send_all_from_account(
            0,
            &node_address,
            Some(asset_a.clone()),
            Some(utxos),
            Some(UtxoStrategy::Default),
        );
        let fee = test_session.get_tx_from_list(0, &txid).fee;
        let sat9 = sat7 - fee;
        test_session.utxo(&btc_key, vec![sat9]);
        test_session.utxo(&asset_a, vec![]);

        // Fund the wallet so that it has 3 assets (including l-btc) and 2 coins per asset.
        test_session.mine_block();

        let sat2_a = 2;
        let sat3_a = 3;
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat2_a, Some(asset_a.clone()));
        test_session.wait_account_tx(0, &txid);
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat3_a, Some(asset_a.clone()));
        test_session.wait_account_tx(0, &txid);

        let sat1_b = 10;
        let asset_b = test_session.node_issueasset(sat1_b);
        let sat2_b = 2;
        let sat3_b = 3;
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat2_b, Some(asset_b.clone()));
        test_session.wait_account_tx(0, &txid);
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat3_b, Some(asset_b.clone()));
        test_session.wait_account_tx(0, &txid);

        let sat10 = 20_000;
        let addr = test_session.get_receive_address(0).address;
        let txid = test_session.node_sendtoaddress(&addr, sat10, None);
        test_session.wait_account_tx(0, &txid);

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
    let mut test_session = setup_session(is_liquid, |_| ());

    assert!(test_session.session.get_subaccount(0).is_ok());
    assert!(test_session.session.get_subaccount(1).is_err());

    // Create subaccounts
    let account1 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 1,
            name: "Account 1".into(),
            // p2wpkh
        })
        .unwrap();
    let account2 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 2,
            name: "Account 2".into(),
            // p2pkh
        })
        .unwrap();
    assert_eq!(account1.account_num, 1);
    assert_eq!(account1.settings.name, "Account 1");
    assert_eq!(account1.script_type, ScriptType::P2wpkh);
    assert_eq!(account1.settings.hidden, false);
    assert_eq!(account2.account_num, 2);
    assert_eq!(account2.settings.name, "Account 2");
    assert_eq!(account2.script_type, ScriptType::P2pkh);
    assert_eq!(account2.settings.hidden, false);
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

    let mut balances: HashMap<u32, u64> = HashMap::new();

    // Send some to account #1
    let sat = 98766;
    let txid = test_session.node_sendtoaddress(&acc1_address.address, sat, None);
    test_session.wait_account_tx(1, &txid);
    *balances.entry(1).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);

    // Send some to account #2
    let sat = 67899;
    let txid = test_session.node_sendtoaddress(&acc2_address.address, sat, None);
    test_session.wait_account_tx(2, &txid);
    *balances.entry(2).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);

    // Send all from account #2 to account #1 (p2pkh -> p2wpkh)
    let txid = test_session.send_all_from_account(
        2,
        &test_session.get_receive_address(1).address,
        None,
        None,
        None,
    );
    test_session.wait_account_tx(1, &txid);
    *balances.entry(1).or_insert(0) += sat - test_session.get_tx_from_list(1, &txid).fee;
    *balances.entry(2).or_insert(0) = 0;
    check_account_balances(&test_session, &balances);

    // Send from account #1 to account #0 (p2wpkh -> p2sh-p2wpkh)
    let sat = 11555;
    let txid = test_session.send_tx_from(1, &acc0_address.address, sat, None);
    test_session.wait_account_tx(0, &txid);
    *balances.entry(1).or_insert(0) -= sat + test_session.get_tx_from_list(1, &txid).fee;
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
    let txid =
        test_session.send_tx_from(0, &test_session.get_receive_address(2).address, sat, None);
    test_session.wait_account_tx(2, &txid);
    *balances.entry(0).or_insert(0) -= sat + test_session.get_tx_from_list(0, &txid).fee;
    *balances.entry(2).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);

    // Must be created using the next available P2PKH account number (skipping over used and reserved numbers)
    let account3 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 18,
            name: "Second PKPH".into(),
        })
        .unwrap();
    assert_eq!(account3.script_type, ScriptType::P2pkh);

    // Should fail - the second P2PKH account is still inactive
    let err = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 34,
            name: "Won't work".into(),
        })
        .unwrap_err();
    assert!(matches!(err, Error::AccountGapsDisallowed));

    // Fund the second P2PKH account, skipping over one address
    let sat = 6666;
    test_session.get_receive_address(18);
    let txid =
        test_session.send_tx_from(0, &test_session.get_receive_address(18).address, sat, None);
    test_session.wait_account_tx(18, &txid);
    *balances.entry(0).or_insert(0) -= sat + test_session.get_tx_from_list(0, &txid).fee;
    *balances.entry(18).or_insert(0) += sat;
    check_account_balances(&test_session, &balances);

    // Should now work
    let account4 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            subaccount: 34,
            name: "Third PKPH".into(),
        })
        .unwrap();
    assert_eq!(account4.script_type, ScriptType::P2pkh);

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
        let network = test_session.network().clone();
        let url = determine_electrum_url_from_net(&network).unwrap();
        let db_root_dir = TempDir::new("electrum_integration_tests").unwrap();
        let db_root = format!("{}", db_root_dir.path().display());
        let proxy = Some("");
        ElectrumSession::create_session(network, &db_root, proxy, url)
    };
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string().into();
    new_session.login(&mnemonic, None).unwrap();

    // Wait until all subaccounts have been recovered
    let mut i = 60;
    let subaccounts = loop {
        assert!(i > 0, "timeout waiting for updates");
        i -= 1;
        let subaccounts = new_session.get_subaccounts().unwrap();
        if subaccounts.len() == balances.len() {
            break subaccounts;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    };

    let btc_key = test_session.btc_key();

    for subaccount in subaccounts.iter() {
        test_session::wait_account_n_txs(&new_session, subaccount.account_num, 1);

        let opt = GetBalanceOpt {
            subaccount: subaccount.account_num,
            num_confs: 0,
            confidential_utxos_only: None,
        };
        let balance = *new_session.get_balance(&opt).unwrap().get(&btc_key).unwrap_or(&0i64) as u64;
        assert_eq!(balance, *balances.get(&subaccount.account_num).unwrap());
    }

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
    let test_session = setup_session(is_liquid, |_| ());

    // Do a transaction so we have some fees to collect, note that this is necessary for Liquid
    // since new blocks do not generate new coins.
    test_session.node_sendtoaddress(&test_session.node_getnewaddress(None), 10000, None);

    // Generate a coinbase sending an output to the wallet.
    test_session.node_generatetoaddress(1, test_session.get_receive_address(0).address);
    test_session.wait_blockheight(102);
    test_session.wait_account_n_txs(0, 1);
    assert!(test_session.balance_account(0, None, None) > 0);
    let txlist = test_session.get_tx_list(0);
    assert_eq!(txlist.len(), 1);
    assert_eq!(txlist[0].fee, 0);

    // This coin is immature though, coinbase outputs cannot be spent until 101 blocks.
}

#[test]
fn registry_liquid() {
    // Get data from asset registry

    let is_liquid = true;
    let mut test_session = setup_session(is_liquid, |_| ());
    let policy_asset = test_session.network.policy_asset.clone().unwrap();

    // Either assets or icons must be requested
    assert!(test_session.refresh_assets(true, false, false).is_err());

    // if refresh=false and no cache, return the sentinel (empty map)

    // refresh false, asset true (no cache), icons true (no cache)
    let value = test_session.refresh_assets(false, true, true).unwrap();
    assert!(value.get("assets").unwrap().as_object().unwrap().is_empty());
    assert!(value.get("icons").unwrap().as_object().unwrap().is_empty());

    // refresh false, asset true (no cache), icons false (no cache)
    let value = test_session.refresh_assets(false, true, false).unwrap();
    assert!(value.get("assets").unwrap().as_object().unwrap().is_empty());
    assert!(value.get("icons").is_none());

    // refresh false, asset false (no cache), icons true (no cache)
    let value = test_session.refresh_assets(false, false, true).unwrap();
    assert!(value.get("assets").is_none());
    assert!(value.get("icons").unwrap().as_object().unwrap().is_empty());

    // refresh true, asset true, icons false (no cache)
    let value = test_session.refresh_assets(true, true, false).unwrap();
    assert!(value.get("assets").unwrap().get(&policy_asset).is_some());
    assert!(value.get("icons").is_none());

    // refresh false, asset false, icons true (no cache)
    let value = test_session.refresh_assets(false, false, true).unwrap();
    assert!(value.get("assets").is_none());
    assert!(value.get("icons").unwrap().as_object().unwrap().is_empty());

    // refresh true, asset true, icons true (no cache)
    // {"asset": data, "icons": data}
    let value = test_session.refresh_assets(true, true, true).unwrap();
    assert!(value.get("assets").unwrap().get(&policy_asset).is_some());
    assert!(value.get("icons").is_some());

    // check 304
    let value = test_session.refresh_assets(true, true, true).unwrap();
    assert!(value.get("assets").unwrap().get(&policy_asset).is_some());
    assert!(value.get("icons").is_some());

    // cache read
    let value = test_session.refresh_assets(false, true, true).unwrap();
    assert!(value.get("assets").unwrap().get(&policy_asset).is_some());
    assert!(value.get("icons").is_some());
}

#[test]
fn labels() {
    // Create a session and two accounts
    let mut test_session = setup_session(false, |_| ());
    let account1 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            name: "Account 1".into(),
            subaccount: 1,
            // p2wpkh
        })
        .unwrap();
    let account2 = test_session
        .session
        .create_subaccount(CreateAccountOpt {
            name: "Account 2".into(),
            subaccount: 2,
            // p2pkh
        })
        .unwrap();

    // Fund account #1
    let acc1_address = test_session.get_receive_address(account1.account_num);
    let txid = test_session.node_sendtoaddress(&acc1_address.address, 9876543, None);
    test_session.wait_account_tx(account1.account_num, &txid);

    // Send from account #1 to account #2 with a memo
    let mut create_opt = CreateTransaction::default();
    create_opt.subaccount = account1.account_num;
    create_opt.addressees.push(AddressAmount {
        address: test_session.get_receive_address(account2.account_num).address,
        satoshi: 50000,
        asset_id: None,
    });
    create_opt.utxos = test_session.utxos(create_opt.subaccount);
    create_opt.memo = Some("Foo, Bar Foo".into());
    let tx = test_session.session.create_transaction(&mut create_opt).unwrap();
    let signed_tx = test_session.session.sign_transaction(&tx).unwrap();
    let txid = test_session.session.broadcast_transaction(&signed_tx.hex).unwrap();
    test_session.wait_account_tx(account1.account_num, &txid);
    test_session.wait_account_tx(account2.account_num, &txid);

    // Memos should be set across all accounts
    assert_eq!(test_session.get_tx_from_list(account1.account_num, &txid).memo, "Foo, Bar Foo");
    assert_eq!(test_session.get_tx_from_list(account2.account_num, &txid).memo, "Foo, Bar Foo");

    test_session.session.set_transaction_memo(&txid, "Bar, Foo Qux").unwrap();
    assert_eq!(test_session.get_tx_from_list(account1.account_num, &txid).memo, "Bar, Foo Qux");
    assert_eq!(test_session.get_tx_from_list(account2.account_num, &txid).memo, "Bar, Foo Qux");

    test_session.stop();
}

#[test]
fn rbf() {
    // Create session/account and fund id
    let mut test_session = setup_session(false, |_| ());
    test_session
        .session
        .create_subaccount(CreateAccountOpt {
            name: "Account 1".into(),
            subaccount: 1,
        })
        .unwrap();
    let txid = test_session.node_sendtoaddress(
        &test_session.get_receive_address(1).address,
        9876543,
        None,
    );
    test_session.wait_account_tx(1, &txid);

    // Create transaction for replacement
    let mut create_opt = CreateTransaction::default();
    let dest_address = test_session.get_receive_address(1).address;
    create_opt.subaccount = 1;
    create_opt.addressees.push(AddressAmount {
        address: dest_address,
        satoshi: 50000,
        asset_id: None,
    });
    create_opt.utxos = test_session.utxos(create_opt.subaccount);
    create_opt.fee_rate = Some(25000);
    create_opt.memo = Some("poz qux".into());
    let tx = test_session.session.create_transaction(&mut create_opt).unwrap();
    let signed_tx = test_session.session.sign_transaction(&tx).unwrap();
    let txid1 = test_session.session.broadcast_transaction(&signed_tx.hex).unwrap();
    test_session.wait_account_tx(1, &txid1);
    let txitem = test_session.get_tx_from_list(1, &txid1);
    assert_eq!(txitem.fee_rate / 1000, 25);

    // Replace it
    let mut create_opt = CreateTransaction::default();
    create_opt.subaccount = 1;
    create_opt.previous_transaction = Some(txitem);
    create_opt.fee_rate = Some(43000);
    let tx = test_session.session.create_transaction(&mut create_opt).unwrap();
    assert!(!tx.user_signed, "tx is marked as user_signed");
    let signed_tx = test_session.session.sign_transaction(&tx).unwrap();
    assert!(signed_tx.user_signed, "tx is not marked as user_signed");
    let txid2 = test_session.session.broadcast_transaction(&signed_tx.hex).unwrap();
    test_session.wait_account_tx(1, &txid2);
    let txitem = test_session.get_tx_from_list(1, &txid2);
    assert_eq!(txitem.fee_rate / 1000, 43);
    assert_eq!(txitem.memo, "poz qux");

    // The old transaction should be gone (after the next sync with the server)
    for i in 0..60 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if test_session.get_tx_list(1).iter().all(|e| e.txhash != txid1) {
            break;
        }
        assert!(i < 59, "timeout waiting for replaced transaction to disappear");
    }

    // Transactions that are not properly signed should be rejected, to prevent the user from
    // being tricked into fee-bumping them.
    let mut tx =
        test_session.electrs.client.transaction_get(&txitem.txhash.parse().unwrap()).unwrap();
    tx.input[0].witness[0][5] = tx.input[0].witness[0][5].wrapping_add(1);
    let tx = BETransaction::Bitcoin(tx);
    let wallet = test_session.session.get_wallet().unwrap();
    let account = wallet.get_account(1).unwrap();
    let is_valid = account.verify_own_txs(&[(tx.txid(), tx)]).unwrap();
    assert_eq!(is_valid, false);

    drop(wallet);
    test_session.stop();
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
    let ap = test_session1.get_receive_address(0);
    let txid = test_session1.node_sendtoaddress(&ap.address, 999999, None);
    test_session1.wait_account_tx(0, &txid);
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

fn setup_forking_sessions(enable_session_cross: bool) -> (TestSession, TestSession) {
    let test_session2 = setup_session(false, |_| ());

    let test_session1 = setup_session(false, |network| {
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

fn setup_session(is_liquid: bool, network_conf: impl FnOnce(&mut Network)) -> TestSession {
    let electrs_exec = if !is_liquid {
        env::var("ELECTRS_EXEC")
            .expect("env ELECTRS_EXEC pointing to electrs executable is required")
    } else {
        env::var("ELECTRS_LIQUID_EXEC")
            .expect("env ELECTRS_LIQUID_EXEC pointing to electrs executable is required")
    };

    let node_exec = if !is_liquid {
        env::var("BITCOIND_EXEC")
            .expect("env BITCOIND_EXEC pointing to elementsd executable is required")
    } else {
        env::var("ELEMENTSD_EXEC")
            .expect("env ELEMENTSD_EXEC pointing to elementsd executable is required")
    };

    env::var("WALLY_DIR").expect("env WALLY_DIR directory containing libwally is required");
    let debug = env::var("DEBUG").is_ok();

    test_session::setup(is_liquid, debug, &electrs_exec, &node_exec, network_conf)
}

fn get_chain(test_session: &mut TestSession) -> HeadersChain {
    test_session.stop();
    let mut path: path::PathBuf = test_session.session.data_root.as_str().into();
    path.push("headers_chain_regtest");
    HeadersChain::new(path, bitcoin::Network::Regtest).unwrap()
}

fn assert_unwrap_invalid(result: spv::CrossValidationResult) -> spv::CrossValidationInvalid {
    match result {
        spv::CrossValidationResult::Invalid(inv) => inv,
        _ => panic!("expected cross-validation to fail"),
    }
}
