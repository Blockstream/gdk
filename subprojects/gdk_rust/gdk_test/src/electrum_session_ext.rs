use std::thread;
use std::time::Duration;

use gdk_common::model::*;
use gdk_common::scripts::ScriptType;
use gdk_electrum::ElectrumSession;

use crate::TestSigner;

pub trait ElectrumSessionExt {
    /// Simulate login through the auth handler
    fn auth_handler_login(&mut self, credentials: &Credentials);

    /// Perform BIP44 account discovery as it is performed in the resolver
    fn discover_subaccounts(&mut self, credentials: &Credentials);

    /// wait for the n txs to show up in the given account
    fn wait_account_n_txs(&self, subaccount: u32, n: usize);
}

impl ElectrumSessionExt for ElectrumSession {
    fn auth_handler_login(&mut self, credentials: &Credentials) {
        let signer =
            TestSigner::new(credentials, self.network.bip32_network(), self.network.liquid);

        // Connect must be done before login
        self.connect(&serde_json::to_value(self.network.clone()).unwrap()).unwrap();

        // Load the rust persisted cache
        let opt = LoadStoreOpt {
            master_xpub: signer.master_xpub(),
            master_xpub_fingerprint: None,
        };
        self.load_store(&opt).unwrap();

        // Set the master blinding key if missing in the cache
        if self.network.liquid {
            if self.get_master_blinding_key().unwrap().master_blinding_key.is_none() {
                // Master blinding key is missing
                let master_blinding_key = signer.master_blinding();
                let opt = SetMasterBlindingKeyOpt {
                    master_blinding_key,
                };
                self.set_master_blinding_key(&opt).unwrap();
            }
        }

        // Set the account xpubs if missing in the cache
        for account_num in self.get_subaccount_nums().unwrap() {
            // Currently, the resolver always asks for the subaccout xpub
            let opt = GetAccountPathOpt {
                subaccount: account_num,
            };
            let path = self.get_subaccount_root_path(opt).unwrap();
            let xpub = signer.account_xpub(&path.path.into());

            let opt = CreateAccountOpt {
                subaccount: account_num,
                name: "".to_string(),
                xpub: Some(xpub),
                discovered: false,
                is_already_created: true,
                allow_gaps: false,
            };
            self.create_subaccount(opt).unwrap();
        }

        // We got everything from the signer
        self.start_threads().unwrap();
    }

    fn discover_subaccounts(&mut self, credentials: &Credentials) {
        let signer =
            TestSigner::new(credentials, self.network.bip32_network(), self.network.liquid);

        for script_type in ScriptType::types() {
            loop {
                let opt = GetNextAccountOpt {
                    script_type: *script_type,
                };
                let account_num = self.get_next_subaccount(opt).unwrap();
                let opt = GetAccountPathOpt {
                    subaccount: account_num,
                };
                let path = self.get_subaccount_root_path(opt).unwrap().path;
                let xpub = signer.account_xpub(&path.into());
                let opt = DiscoverAccountOpt {
                    script_type: *script_type,
                    xpub,
                };
                if self.discover_subaccount(opt).unwrap() {
                    let opt = CreateAccountOpt {
                        subaccount: account_num,
                        xpub: Some(xpub),
                        discovered: true,
                        ..Default::default()
                    };
                    self.create_subaccount(opt).unwrap();
                } else {
                    // Empty subaccount
                    break;
                }
            }
        }
    }

    fn wait_account_n_txs(&self, subaccount: u32, n: usize) {
        let mut opt = GetTransactionsOpt::default();
        opt.subaccount = subaccount;
        opt.count = n;
        for _ in 0..10 {
            if self.get_transactions(&opt).unwrap().0.len() >= n {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
        panic!("timeout waiting for {} txs to show up in account {}", n, subaccount);
    }
}
