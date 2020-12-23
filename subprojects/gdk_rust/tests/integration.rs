use gdk_common::model::{RefreshAssets, SPVVerifyResult};
use gdk_common::session::Session;
use gdk_electrum::headers::bitcoin::HeadersChain;
use gdk_electrum::interface::ElectrumUrl;
use gdk_electrum::spv;

use log::info;
use std::{env, path};

mod test_session;
use test_session::TestSession;

static MEMO1: &str = "hello memo";
static MEMO2: &str = "hello memo2";

#[test]
fn bitcoin() {
    let electrs_exec = env::var("ELECTRS_EXEC")
        .expect("env ELECTRS_EXEC pointing to electrs executable is required");
    let node_exec = env::var("BITCOIND_EXEC")
        .expect("env BITCOIND_EXEC pointing to elementsd executable is required");
    env::var("WALLY_DIR").expect("env WALLY_DIR directory containing libwally is required");
    let debug = env::var("DEBUG").is_ok();

    let mut test_session = test_session::setup(false, debug, &electrs_exec, &node_exec, 0, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));
    let node_bech32_address = test_session.node_getnewaddress(Some("bech32"));
    let node_legacy_address = test_session.node_getnewaddress(Some("legacy"));
    test_session.fund(100_000_000, None);
    test_session.get_subaccount();
    let txid = test_session.send_tx(&node_address, 10_000, None, Some(MEMO1.to_string()), None); // p2shwpkh
    test_session.test_set_get_memo(&txid, MEMO1, MEMO2);
    test_session.is_verified(&txid, SPVVerifyResult::Unconfirmed);
    test_session.send_tx(&node_bech32_address, 10_000, None, None, None); // p2wpkh
    test_session.send_tx(&node_legacy_address, 10_000, None, None, None); // p2pkh
    test_session.send_all(&node_legacy_address, None);
    test_session.mine_block();
    test_session.send_tx_same_script();
    test_session.fund(100_000_000, None);
    test_session.send_multi(3, 100_000, &vec![]);
    test_session.send_multi(30, 100_000, &vec![]);
    test_session.mine_block();
    test_session.send_fails();
    test_session.fees();
    test_session.settings();
    test_session.is_verified(&txid, SPVVerifyResult::Verified);
    test_session.reconnect();
    test_session.spv_verify_tx(&txid, 102);
    test_session.test_set_get_memo(&txid, MEMO2, ""); // after reconnect memo has been reloaded from disk
    let mut utxos = test_session.utxo("btc", vec![149741, 96697489]);
    test_session.check_decryption(103, &[&txid]);

    utxos.0.get_mut("btc").unwrap().retain(|e| e.satoshi == 149741); // we want to use the smallest utxo
    test_session.send_tx(&node_legacy_address, 10_000, None, None, Some(utxos));
    test_session.utxo("btc", vec![139573, 96697489]); // the smallest utxo has been spent
                                                      // TODO add a test with external UTXO

    test_session.stop();
}

#[test]
fn liquid() {
    let electrs_exec = env::var("ELECTRS_LIQUID_EXEC")
        .expect("env ELECTRS_LIQUID_EXEC pointing to electrs executable is required");
    let node_exec = env::var("ELEMENTSD_EXEC")
        .expect("env ELEMENTSD_EXEC pointing to elementsd executable is required");
    env::var("WALLY_DIR").expect("env WALLY_DIR directory containing libwally is required");
    let debug = env::var("DEBUG").is_ok();

    let mut test_session = test_session::setup(true, debug, &electrs_exec, &node_exec, 0, |_| ());

    let node_address = test_session.node_getnewaddress(Some("p2sh-segwit"));
    let node_bech32_address = test_session.node_getnewaddress(Some("bech32"));
    let node_legacy_address = test_session.node_getnewaddress(Some("legacy"));

    let assets = test_session.fund(100_000_000, Some(1));
    test_session.send_tx_to_unconf();
    test_session.get_subaccount();
    let txid = test_session.send_tx(&node_address, 10_000, None, Some(MEMO1.to_string()), None);
    test_session.check_decryption(101, &[&txid]);
    test_session.test_set_get_memo(&txid, MEMO1, MEMO2);
    test_session.is_verified(&txid, SPVVerifyResult::Unconfirmed);
    test_session.send_tx(&node_bech32_address, 10_000, None, None, None);
    test_session.send_tx(&node_legacy_address, 10_000, None, None, None);
    test_session.send_tx(&node_address, 10_000, Some(assets[0].clone()), None, None);
    test_session.send_tx(&node_address, 100, Some(assets[0].clone()), None, None); // asset should send below dust limit
    test_session.send_all(&node_address, Some(assets[0].to_string()));
    test_session.send_all(&node_address, test_session.asset_tag());
    test_session.mine_block();
    let assets = test_session.fund(100_000_000, Some(3));
    test_session.send_multi(3, 100_000, &vec![]);
    test_session.send_multi(30, 100_000, &assets);
    test_session.mine_block();
    test_session.send_fails();
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
        vec![99652226, 1_000_000],
    );
    utxos
        .0
        .get_mut("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
        .unwrap()
        .retain(|e| e.satoshi == 1_000_000); // we want to use the smallest utxo
    test_session.send_tx(&node_legacy_address, 10_000, None, None, Some(utxos));
    test_session.utxo(
        "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
        vec![989748, 99652226],
    ); // the smallest utxo has been spent

    // test_session.check_decryption(103, &[&txid]); // TODO restore after sorting out https://github.com/ElementsProject/rust-elements/pull/61

    test_session.refresh_assets(&RefreshAssets::new(true, true, true)); // check 200
    test_session.refresh_assets(&RefreshAssets::new(true, true, true)); // check 304
    test_session.refresh_assets(&RefreshAssets::new(true, false, true)); // check partial request
    test_session.refresh_assets(&RefreshAssets::new(false, true, false)); // check local read

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
        test_session1.wait_block_status_change();
        test_session2.wait_block_status_change();
        assert_eq!(test_session1.session.block_status().unwrap().0, 126);
        assert_eq!(test_session2.session.block_status().unwrap().0, 1141);

        // Grab direct access to session1's HeadersChain
        let session1_chain = get_chain(&mut test_session1);
        assert_eq!(session1_chain.height(), 126);

        // Cross-validate session1's chain against session'2 electrum server
        let session2_electrum_url = ElectrumUrl::Plaintext(test_session2.electrs_url.clone());
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
        test_session2.wait_block_status_change();

        // Grab direct access to session1's HeadersChain
        let session1_chain = get_chain(&mut test_session1);
        assert_eq!(session1_chain.height(), 121);

        // Cross-validate session1's chain against session'2 electrum server
        let session2_electrum_url = ElectrumUrl::Plaintext(test_session2.electrs_url.clone());
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
    let ap = test_session1.session.get_receive_address(&serde_json::Value::Null).unwrap();
    let txid = test_session1.node_sendtoaddress(&ap.address, 999999, None);
    test_session1.wait_tx_status_change();
    let txitem = test_session1.get_tx_from_list(&txid);
    assert_eq!(txitem.block_height, 0);
    assert_eq!(txitem.spv_verified, "unconfirmed");
    info!("sent mempool tx");

    // Confirm it, wait for it to SPV-validate
    test_session1.node_generate(1);
    test_session1.wait_block_status_change();
    test_session1.wait_tx_spv_change(&txid, "verified");
    assert_eq!(test_session1.get_tx_from_list(&txid).block_height, 122);
    info!("tx confirmed and spv validated");

    // Extend session2, putting session1 on a minority fork
    test_session2.node_generate(10);
    test_session1.wait_block_status_change();
    let cross_result = test_session1.wait_spv_cross_validation_change(false);
    let inv = assert_unwrap_invalid(cross_result);
    assert_eq!(inv.common_ancestor, 121);
    assert_eq!(inv.longest_height, 131);
    assert_eq!(test_session1.get_tx_from_list(&txid).spv_verified, "not_longest");
    info!("extended session2, making session1 the minority");

    // Extend session1, making it the best chain
    test_session1.node_generate(11);
    let cross_result = test_session1.wait_spv_cross_validation_change(true);
    assert!(cross_result.is_valid());
    assert_eq!(test_session1.get_tx_from_list(&txid).spv_verified, "verified");
    assert_eq!(test_session1.session.block_status().unwrap().0, 133);
    info!("extended session1, making session1 the majority");

    // Make session1 the minority again
    test_session2.node_generate(3);
    let cross_result = test_session1.wait_spv_cross_validation_change(false);
    let inv = assert_unwrap_invalid(cross_result);
    assert_eq!(inv.common_ancestor, 121);
    assert_eq!(inv.longest_height, 134);
    assert_eq!(test_session1.get_tx_from_list(&txid).spv_verified, "not_longest");
    info!("extended session2, making session1 the minority (again)");

    // Reorg session1 into session2, pointing both to the same longest chain
    // Cross-validation should now succeed, but our tx should now appear as unconfirmed again
    test_session1.node_connect(test_session2.p2p_port);
    let cross_result = test_session1.wait_spv_cross_validation_change(true);
    assert!(cross_result.is_valid());
    let txitem = test_session1.get_tx_from_list(&txid);
    assert_eq!(txitem.block_height, 0);
    assert_eq!(txitem.spv_verified, "unconfirmed");
    info!("reorged session1 into session2, tx is unconfirmed again");

    // Re-confirm the tx and then re-fork the chain, such that the tx is confirmed before the forking point
    // Cross-validation should fail, but the tx should still appear as SPV-validated
    test_session1.node_generate(1);
    test_session1.wait_tx_spv_change(&txid, "verified");
    assert_eq!(test_session1.get_tx_from_list(&txid).block_height, 135);
    test_session1.node_disconnect_all();
    test_session1.node_generate(5);
    test_session2.node_generate(10);
    let cross_result = test_session1.wait_spv_cross_validation_change(false);
    let inv = assert_unwrap_invalid(cross_result);
    assert_eq!(inv.common_ancestor, 135);
    assert_eq!(inv.longest_height, 145);
    let txitem = test_session1.get_tx_from_list(&txid);
    assert_eq!(txitem.block_height, 135);
    assert_eq!(txitem.spv_verified, "verified");

    test_session1.stop();
    test_session2.stop();
}

fn setup_forking_sessions(enable_session_cross: bool) -> (TestSession, TestSession) {
    let electrs_exec = env::var("ELECTRS_EXEC")
        .expect("env ELECTRS_EXEC pointing to electrs executable is required");
    let node_exec = env::var("BITCOIND_EXEC")
        .expect("env BITCOIND_EXEC pointing to elementsd executable is required");
    env::var("WALLY_DIR").expect("env WALLY_DIR directory containing libwally is required");
    let debug = env::var("DEBUG").is_ok();

    let mut test_session2 = test_session::setup(false, debug, &electrs_exec, &node_exec, 2, |_| ());

    let mut test_session1 =
        test_session::setup(false, debug, &electrs_exec, &node_exec, 1, |network| {
            if enable_session_cross {
                network.spv_cross_validation = Some(true);
                network.spv_cross_validation_servers =
                    Some(vec![test_session2.electrs_url.clone()]);
            }
        });

    // Connect nodes and point both to the same tip
    test_session2.node_connect(test_session1.p2p_port);
    test_session1.node_generate(20);

    test_session1.wait_block_status_change();
    test_session2.wait_block_status_change();
    assert_eq!(test_session2.session.block_status().unwrap().0, 121);
    assert_eq!(test_session2.session.block_status().unwrap().0, 121);

    // Disconnect so they don't learn about eachother blocks
    test_session1.node_disconnect_all();

    (test_session1, test_session2)
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
