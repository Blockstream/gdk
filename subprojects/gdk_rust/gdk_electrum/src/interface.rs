use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use serde::{Deserialize, Serialize};

use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::{
    AddressPointer, Balances, CreateAccountOpt, CreateTransaction, GetBalanceOpt,
    GetTransactionsOpt, GetUnspentOpt, Settings, TransactionMeta, UpdateAccountOpt,
};
use gdk_common::network::Network;
use gdk_common::scripts::ScriptType;
use gdk_common::wally::*;

use crate::account::{
    discover_accounts, get_account_script_purpose, get_last_next_account_nums, Account,
};
use crate::error::*;
use crate::store::*;

use electrum_client::{Client, ConfigBuilder};
use gdk_common::be::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::str::FromStr;

pub struct WalletCtx {
    pub secp: Secp256k1<All>,
    pub network: Network,
    pub mnemonic: Mnemonic,
    pub store: Store,
    pub master_xprv: ExtendedPrivKey,
    pub master_xpub: ExtendedPubKey,
    pub master_blinding: Option<MasterBlindingKey>,
    pub accounts: HashMap<u32, Account>,
    pub change_max_deriv: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ElectrumUrl {
    Tls(String, bool), // the bool value indicates if the domain name should be validated
    Plaintext(String),
}

impl ElectrumUrl {
    pub fn build_client(&self, proxy: Option<&str>) -> Result<Client, Error> {
        let mut config = ConfigBuilder::new();
        if let Some(proxy) = proxy {
            // TODO: add support for credentials?
            config = config.socks5(Some(electrum_client::Socks5Config::new(proxy)))?;
        }
        self.build_config(config)
    }

    pub fn build_config(&self, config: ConfigBuilder) -> Result<Client, Error> {
        let (url, config) = match self {
            ElectrumUrl::Tls(url, validate) => {
                (format!("ssl://{}", url), config.validate_domain(*validate))
            }
            ElectrumUrl::Plaintext(url) => (format!("tcp://{}", url), config),
        };
        Ok(Client::from_config(&url, config.build())?)
    }

    pub fn url(&self) -> &str {
        match self {
            ElectrumUrl::Tls(url, _) => url,
            ElectrumUrl::Plaintext(url) => url,
        }
    }
}

// Parse the standard <host>:<port>:<t|s> string format,
// with an optional non-standard `:noverify` suffix to skip tls validation
impl FromStr for ElectrumUrl {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let mk_err = || Error::InvalidElectrumUrl(s.into());
        let mut parts = s.split(":");
        let hostname = parts.next().ok_or_else(mk_err)?;
        let port: u16 = parts.next().ok_or_else(mk_err)?.parse().map_err(|_| mk_err())?;
        let proto = parts.next().unwrap_or("t");
        let validate_tls = parts.next() != Some("noverify");

        let url = format!("{}:{}", hostname, port);
        Ok(match proto {
            "s" => ElectrumUrl::Tls(url, validate_tls),
            "t" => ElectrumUrl::Plaintext(url),
            _ => return Err(mk_err()),
        })
    }
}

impl WalletCtx {
    pub fn new(
        store: Store,
        mnemonic: Mnemonic,
        network: Network,
        master_xprv: ExtendedPrivKey,
        master_xpub: ExtendedPubKey,
        master_blinding: Option<MasterBlindingKey>,
    ) -> Result<Self, Error> {
        let mut wallet = WalletCtx {
            mnemonic,
            store: store.clone(),
            network, // TODO: from db
            secp: Secp256k1::gen_new(),
            master_xprv,
            master_xpub,
            master_blinding,
            accounts: Default::default(),
            change_max_deriv: 0,
        };
        let account_nums = store.read()?.account_nums();
        for account_num in account_nums {
            wallet._ensure_account(account_num)?;
        }
        wallet._ensure_account(0)?;
        Ok(wallet)
    }

    pub fn get_mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    pub fn get_account(&self, account_num: u32) -> Result<&Account, Error> {
        self.accounts.get(&account_num).ok_or_else(|| Error::InvalidSubaccount(account_num))
    }

    pub fn iter_accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    pub fn iter_accounts_sorted(&self) -> impl Iterator<Item = &Account> {
        let mut accounts = self.accounts.iter().collect::<Vec<_>>();
        accounts.sort_unstable_by(|(a_num, _), (b_num, _)| a_num.cmp(b_num));
        accounts.into_iter().map(|(_, account)| account)
    }

    pub fn get_next_subaccount(&self, script_type: ScriptType) -> u32 {
        let (_last_account, next_account) =
            get_last_next_account_nums(self.accounts.keys().copied().collect(), script_type);
        next_account
    }

    pub fn create_account(&mut self, opt: CreateAccountOpt) -> Result<&Account, Error> {
        // Check that the given subaccount number is the next available one for its script type.
        let (script_type, _) = get_account_script_purpose(opt.subaccount)?;
        let (last_account, next_account) =
            get_last_next_account_nums(self.accounts.keys().copied().collect(), script_type);

        if opt.subaccount != next_account {
            // The subaccount already exists, or skips over the next available subaccount number
            bail!(Error::InvalidSubaccount(opt.subaccount));
        }
        if let Some(last_account) = last_account {
            // This is the next subaccount number, but the last one is still unused
            if !self.accounts.get(&last_account).unwrap().has_transactions() {
                bail!(Error::AccountGapsDisallowed);
            }
        }

        let account = self._ensure_account(opt.subaccount)?;
        account.set_name(&opt.name)?;
        Ok(account)
    }

    pub fn update_account(&mut self, opt: UpdateAccountOpt) -> Result<(), Error> {
        self.get_account(opt.subaccount)?.set_settings(opt)
    }

    pub fn recover_accounts(
        &mut self,
        electrum_url: &ElectrumUrl,
        proxy: Option<&str>,
    ) -> Result<(), Error> {
        let account_nums = discover_accounts(
            &self.master_xprv,
            self.network.id(),
            electrum_url,
            proxy,
            self.master_blinding.as_ref(),
        )?;
        for account_num in account_nums {
            self._ensure_account(account_num)?;
        }
        Ok(())
    }

    fn _ensure_account(&mut self, account_num: u32) -> Result<&mut Account, Error> {
        Ok(match self.accounts.entry(account_num) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Account::new(
                self.network.clone(),
                &self.master_xprv,
                self.master_blinding.clone(),
                self.store.clone(),
                account_num,
            )?),
        })
    }

    pub fn get_settings(&self) -> Result<Settings, Error> {
        Ok(self.store.read()?.get_settings().unwrap_or_default())
    }

    pub fn change_settings(&self, settings: &Settings) -> Result<(), Error> {
        self.store.write()?.insert_settings(Some(settings.clone()))?;
        Ok(())
    }

    pub fn get_tip(&self) -> Result<(u32, BEBlockHash), Error> {
        Ok(self.store.read()?.cache.tip)
    }

    pub fn list_tx(&self, opt: &GetTransactionsOpt) -> Result<Vec<TransactionMeta>, Error> {
        self.get_account(opt.subaccount)?.list_tx(opt)
    }

    pub fn utxos(&self, opt: &GetUnspentOpt) -> Result<Utxos, Error> {
        // TODO does not support the `all_coins` option
        self.get_account(opt.subaccount)?
            .utxos(opt.num_confs.unwrap_or(0), opt.confidential_utxos_only.unwrap_or(false))
    }

    pub fn balance(&self, opt: &GetBalanceOpt) -> Result<Balances, Error> {
        self.get_account(opt.subaccount)?
            .balance(opt.num_confs, opt.confidential_utxos_only.unwrap_or(false))
    }

    pub fn create_tx(&self, request: &mut CreateTransaction) -> Result<TransactionMeta, Error> {
        self.get_account(request.subaccount)?.create_tx(request)
    }

    pub fn sign(&self, request: &TransactionMeta) -> Result<TransactionMeta, Error> {
        let account_num = request
            .create_transaction
            .as_ref()
            .ok_or_else(|| Error::Generic("Cannot sign without tx data".into()))?
            .subaccount;
        self.get_account(account_num)?.sign(request)
    }

    pub fn get_next_address(&self, account_num: u32) -> Result<AddressPointer, Error> {
        self.get_account(account_num)?.get_next_address()
    }

    pub fn get_asset_icons(&self) -> Result<Option<serde_json::Value>, Error> {
        self.store.read()?.read_asset_icons()
    }
    pub fn get_asset_registry(&self) -> Result<Option<serde_json::Value>, Error> {
        self.store.read()?.read_asset_registry()
    }
}

#[cfg(test)]
mod test {
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
    use bitcoin::util::bip143::SigHashCache;
    use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::util::key::PrivateKey;
    use bitcoin::util::key::PublicKey;
    use bitcoin::Script;
    use bitcoin::{Address, Network, SigHashType, Transaction};
    use gdk_common::scripts::p2shwpkh_script_sig;
    use std::str::FromStr;

    fn p2pkh_hex(pk: &str) -> (PublicKey, Script) {
        let pk = hex::decode(pk).unwrap();
        let pk = PublicKey::from_slice(pk.as_slice()).unwrap();
        let witness_script = Address::p2pkh(&pk, Network::Bitcoin).script_pubkey();
        (pk, witness_script)
    }

    #[test]
    fn test_bip() {
        let secp: Secp256k1<All> = Secp256k1::gen_new();

        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
        let tx_bytes = hex::decode("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let private_key_bytes =
            hex::decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
                .unwrap();

        let key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let private_key = PrivateKey {
            compressed: true,
            network: Network::Testnet,
            key,
        };

        let (public_key, witness_script) =
            p2pkh_hex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
        assert_eq!(
            hex::encode(witness_script.to_bytes()),
            "76a91479091972186c449eb1ded22b78e40d009bdf008988ac"
        );
        let value = 1_000_000_000;
        let hash =
            SigHashCache::new(&tx).signature_hash(0, &witness_script, value, SigHashType::All);

        assert_eq!(
            &hash.into_inner()[..],
            &hex::decode("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6")
                .unwrap()[..],
        );

        let signature = secp.sign(&Message::from_slice(&hash[..]).unwrap(), &private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        assert_eq!(signature_hex, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01");

        let script_sig = p2shwpkh_script_sig(&public_key);

        assert_eq!(
            format!("{}", hex::encode(script_sig.as_bytes())),
            "16001479091972186c449eb1ded22b78e40d009bdf0089"
        );
    }

    #[test]
    fn test_my_tx() {
        let secp: Secp256k1<All> = Secp256k1::gen_new();
        let xprv = ExtendedPrivKey::from_str("tprv8jdzkeuCYeH5hi8k2JuZXJWV8sPNK62ashYyUVD9Euv5CPVr2xUbRFEM4yJBB1yBHZuRKWLeWuzH4ptmvSgjLj81AvPc9JhV4i8wEfZYfPb").unwrap();
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);
        let private_key = xprv.private_key;
        let public_key = xpub.public_key;
        let public_key_bytes = public_key.to_bytes();
        let public_key_str = format!("{}", hex::encode(&public_key_bytes));

        let address = Address::p2shwpkh(&public_key, Network::Testnet).unwrap();
        assert_eq!(format!("{}", address), "2NCEMwNagVAbbQWNfu7M7DNGxkknVTzhooC");

        assert_eq!(
            public_key_str,
            "0386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc"
        );
        let tx_hex = "020000000001010e73b361dd0f0320a33fd4c820b0c7ac0cae3b593f9da0f0509cc35de62932eb01000000171600141790ee5e7710a06ce4a9250c8677c1ec2843844f0000000002881300000000000017a914cc07bc6d554c684ea2b4af200d6d988cefed316e87a61300000000000017a914fda7018c5ee5148b71a767524a22ae5d1afad9a9870247304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01210386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc00000000";

        let tx_bytes = hex::decode(tx_hex).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let (_, witness_script) = p2pkh_hex(&public_key_str);
        assert_eq!(
            hex::encode(witness_script.to_bytes()),
            "76a9141790ee5e7710a06ce4a9250c8677c1ec2843844f88ac"
        );
        let value = 10_202;
        let hash =
            SigHashCache::new(&tx).signature_hash(0, &witness_script, value, SigHashType::All);

        assert_eq!(
            &hash.into_inner()[..],
            &hex::decode("58b15613fc1701b2562430f861cdc5803531d08908df531082cf1828cd0b8995")
                .unwrap()[..],
        );

        let signature = secp.sign(&Message::from_slice(&hash[..]).unwrap(), &private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        let signature = hex::decode(&signature_hex).unwrap();

        assert_eq!(signature_hex, "304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01");
        assert_eq!(tx.input[0].witness[0], signature);
        assert_eq!(tx.input[0].witness[1], public_key_bytes);

        let script_sig = p2shwpkh_script_sig(&public_key);
        assert_eq!(tx.input[0].script_sig, script_sig);
    }
}
