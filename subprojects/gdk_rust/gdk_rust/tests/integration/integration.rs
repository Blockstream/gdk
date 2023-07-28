use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use electrsd::electrum_client::ElectrumApi;
use gdk_common::log::info;
use serde_json::Value;
use tempfile::TempDir;

use gdk_common::model::*;
use gdk_common::session::Session;
use gdk_common::{NetworkParameters, State};
use gdk_electrum::headers::bitcoin::HeadersChain;
use gdk_electrum::interface::ElectrumUrl;
use gdk_electrum::{headers, spv, ElectrumSession};
use gdk_test::utils;
use gdk_test::RpcNodeExt;
use gdk_test::TestSession;

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
        let network = test_session.session.network_parameters().clone();
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

        // The previous wait_blockheight is based on data kept in memory while
        // the following assert check the file on disk that may have not been written yet.
        // This is not elegant but we are going to move this test anyway so this is a workaround
        // to improve flakyness in the meantime
        thread::sleep(Duration::from_secs(3));

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
fn test_spv_over_period() {
    // regtest doesn't retarget after a period (2016 blocks)
    let mut test_session = TestSession::new(false, |_| ());

    test_session.fund(100_000_000, None);

    let initial_block = 101;
    let block_to_mine = 200;
    let times = 10;

    for i in 1..(times + 1) {
        // generating all blocks at once may cause rpc timeout
        test_session.node_generate(block_to_mine);
        test_session.wait_blockheight(initial_block + i * block_to_mine);
    }

    let satoshi = 10_000;
    let ap = test_session.get_receive_address(0);
    let txid = test_session.node.client.sendtoaddress(&ap.address, satoshi, None).unwrap();
    test_session.wait_tx(vec![0], &txid, Some(satoshi), Some(TransactionType::Incoming));
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

    test_session.fund(100_000_000, None);

    let initial_block = 101u32;

    let mut txids = vec![];
    let satoshi = 10_000;
    for _ in 0..10u32 {
        let ap = test_session.get_receive_address(0);
        let txid = test_session.node.client.sendtoaddress(&ap.address, satoshi, None).unwrap();
        test_session.wait_tx(vec![0], &txid, Some(satoshi), Some(TransactionType::Incoming));
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
