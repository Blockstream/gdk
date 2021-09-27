use crate::be::BEBlockHash;
use crate::mnemonic::Mnemonic;
use crate::model::*;
use crate::password::Password;

// TODO: remove all json Values from our Session
use serde_json::Value;

pub trait Session<E> {
    // fn create_session(network: Network) -> Result<Self::Value, E>;
    fn poll_session(&self) -> Result<(), E>;
    fn connect(&mut self, net_params: &Value) -> Result<(), E>;
    fn disconnect(&mut self) -> Result<(), E>;
    fn login(&mut self, mnemonic: &Mnemonic, password: Option<Password>) -> Result<LoginData, E>;
    fn mnemonic_from_pin_data(&mut self, pin: String, details: PinGetDetails) -> Result<String, E>;
    fn get_subaccounts(&self) -> Result<Vec<AccountInfo>, E>;
    fn get_subaccount(&self, index: u32) -> Result<AccountInfo, E>;
    fn create_subaccount(&mut self, opt: CreateAccountOpt) -> Result<AccountInfo, E>;
    fn get_next_subaccount(&self, opt: GetNextAccountOpt) -> Result<u32, E>;
    /// Deprecated in favor of update_subaccount
    fn rename_subaccount(&mut self, opt: RenameAccountOpt) -> Result<(), E>;
    fn update_subaccount(&mut self, opt: UpdateAccountOpt) -> Result<(), E>;
    fn set_subaccount_hidden(&mut self, opt: SetAccountHiddenOpt) -> Result<(), E>;
    fn get_transactions(&self, opt: &GetTransactionsOpt) -> Result<TxsResult, E>;
    fn get_raw_transaction_details(&self, txid: &str) -> Result<Value, E>;
    fn get_balance(&self, opt: &GetBalanceOpt) -> Result<Balances, E>;
    fn set_transaction_memo(&self, txid: &str, memo: &str) -> Result<(), E>;
    fn create_transaction(&mut self, details: &mut CreateTransaction)
        -> Result<TransactionMeta, E>;
    fn sign_transaction(&self, tx_detail_unsigned: &TransactionMeta) -> Result<TransactionMeta, E>;
    fn send_transaction(
        &mut self,
        tx_detail_signed: &TransactionMeta,
    ) -> Result<TransactionMeta, E>;
    fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, E>;
    fn get_receive_address(&self, opt: &GetAddressOpt) -> Result<AddressPointer, E>;
    fn get_mnemonic(&self) -> Result<Mnemonic, E>;
    fn get_available_currencies(&self) -> Result<Value, E>;
    fn get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, E>;
    fn get_settings(&self) -> Result<Settings, E>;
    fn change_settings(&mut self, value: &Value) -> Result<(), E>;
    fn refresh_assets(&self, details: &RefreshAssets) -> Result<Value, E>;
    fn block_status(&self) -> Result<(u32, BEBlockHash), E>;
    fn tx_status(&self) -> Result<u64, E>;
    fn set_pin(&self, details: &PinSetDetails) -> Result<PinGetDetails, E>;
    fn get_unspent_outputs(&self, opt: &GetUnspentOpt) -> Result<GetUnspentOutputs, E>;
}
