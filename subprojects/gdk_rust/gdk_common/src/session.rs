use crate::mnemonic::Mnemonic;
use crate::model::*;
use crate::password::Password;

// TODO: remove all json Values from our Session
use serde_json::Value;

pub trait Session<E> {
    // fn create_session(network: Network) -> Result<Self::Value, E>;
    fn destroy_session(&mut self) -> Result<(), E>;
    fn poll_session(&self) -> Result<(), E>;
    fn connect(&mut self, net_params: &Value) -> Result<(), E>;
    fn disconnect(&mut self) -> Result<(), E>;
    // fn register_user(&mut self, mnemonic: String) -> Result<(), E>;
    fn login(
        &mut self,
        mnemonic: &Mnemonic,
        password: Option<Password>,
    ) -> Result<Vec<Notification>, E>;
    fn login_with_pin(
        &mut self,
        pin: String,
        details: PinGetDetails,
    ) -> Result<Vec<Notification>, E>;
    fn get_subaccounts(&self) -> Result<Vec<Subaccount>, E>;
    fn get_subaccount(&self, index: u32, num_confs: u32) -> Result<Subaccount, E>;
    fn get_transactions(&self, opt: &GetTransactionsOpt) -> Result<TxsResult, E>;
    fn get_transaction_details(&self, txid: &str) -> Result<Value, E>;
    fn get_balance(&self, num_confs: u32, subaccount: Option<u32>) -> Result<Balances, E>;
    fn set_transaction_memo(&self, txid: &str, memo: &str, memo_type: u32) -> Result<(), E>;
    fn create_transaction(&mut self, details: &mut CreateTransaction)
        -> Result<TransactionMeta, E>;
    fn sign_transaction(&self, tx_detail_unsigned: &TransactionMeta) -> Result<TransactionMeta, E>;
    fn send_transaction(&mut self, tx_detail_signed: &TransactionMeta) -> Result<String, E>;
    fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, E>;
    fn get_receive_address(&self, addr_details: &Value) -> Result<AddressPointer, E>;
    fn get_mnemonic(&self) -> Result<&Mnemonic, E>;
    fn get_available_currencies(&self) -> Result<Value, E>;
    fn get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, E>;
    fn get_settings(&self) -> Result<Settings, E>;
    fn change_settings(&mut self, settings: &Settings) -> Result<(), E>;
    fn refresh_assets(&self, details: &RefreshAssets) -> Result<Value, E>;
    fn block_status(&self) -> Result<(u32, bitcoin::BlockHash), E>;
    fn tx_status(&self) -> Result<u64, E>;
    fn set_pin(&self, details: &PinSetDetails) -> Result<PinGetDetails, E>;
    fn get_unspent_outputs(&self, details: &Value) -> Result<GetUnspentOutputs, E>;
}
