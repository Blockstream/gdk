use std::env;
mod test_session;

#[test]
fn integration_bitcoin() {
    let electrs_exec = env::var("ELECTRS_EXEC")
        .expect("env ELECTRS_EXEC pointing to electrs executable is required");
    let node_exec = env::var("BITCOIND_EXEC")
        .expect("env BITCOIND_EXEC pointing to elementsd executable is required");
    env::var("WALLY_DIR").expect("env WALLY_DIR directory containing libwally is required");
    let debug = env::var("DEBUG").is_ok();

    let mut test_session = test_session::setup(false, debug, electrs_exec, node_exec);

    let node_address = test_session.node_getnewaddress();
    test_session.fund(100_000_000);
    test_session.send_tx(&node_address, 10_000);
    test_session.send_all(&node_address, None);
    test_session.mine_block();
    test_session.send_tx_same_script();
    test_session.fund(100_000_000);
    test_session.send_multi(3, 100_000);
    test_session.send_multi(30, 100_000);
    test_session.mine_block();
    test_session.send_fails();
    test_session.fees();
    test_session.settings();

    test_session.stop();
}
