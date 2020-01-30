use crate::GDKRUST_session;
use gdk_common::Session;
use serde_json::Value;
use gdk_common::network::Network;


macro_rules! impl_enum_method_body {
    ($name:ident, $self:ty, $ret:ty, $( $param:ident:$type:ty ),* ) => {
        fn $name(self: $self, $( $param:$type, )*) -> $ret {
            match self {
                GDKRUST_session::Rpc(x) => x.$name($( $param, )*),
                //GDKRUST_session::Electrum(x) => x.$name($( $param, )*),
            }.map_err(|e| format!("{:?}", e))
        }
    };
}

macro_rules! impl_enum_method {
    ($name:ident, $ret:ty, $( $param:ident:$type:ty ),* ) => {
        impl_enum_method_body!($name, &Self, $ret, $( $param:$type ),* );
    };

    ($name:ident, $( $param:ident:$type:ty ),* ) => {
        impl_enum_method_body!($name, &Self, (), $( $param:$type ),* );
    };

    ($name:ident) => {
        impl_enum_method_body!($name, &Self, (), );
    };

    ($name:ident, $ret:ty ) => {
        impl_enum_method_body!($name, &Self, $ret, );
    };
}

macro_rules! impl_mut_enum_method {
    ($name:ident, $ret:ty, $( $param:ident:$type:ty ),* ) => {
        impl_enum_method_body!($name, &mut Self, $ret, $( $param:$type ),* );
    };

    ($name:ident, $( $param:ident:$type:ty ),* ) => {
        impl_enum_method_body!($name, &mut Self, (), $( $param:$type ),* );
    };

    ($name:ident) => {
        impl_enum_method_body!($name, &mut Self, (), );
    };

    ($name:ident, $ret:ty ) => {
        impl_enum_method_body!($name, &mut Self, $ret, );
    };
}

impl Session<String> for GDKRUST_session {
    fn create_session(_network: Network) -> Result<Self, String> {
        unimplemented!();
    }
    fn destroy_session(self) -> Result<(), String> {
        match self {
            GDKRUST_session::Rpc(s) => s.destroy_session(),
            //GDKRUST_session::Electrum(s) => s.destroy_session(),
        }.map_err(|e| format!("{:?}", e))
    }
    impl_enum_method!(poll_session,Result<(), String>);
    impl_mut_enum_method!(connect,Result<(), String>, net_params: Value, log_level: u32);
    impl_mut_enum_method!(disconnect,Result<(), String>);
    impl_mut_enum_method!(register_user,Result<(), String>, mnemonic: String);
    impl_mut_enum_method!(login,Result<(), String>, mnemonic: String, password: Option<String>);
    impl_enum_method!(get_subaccounts,Result<Vec<Value>, String>);
    impl_enum_method!(get_subaccount,Result<Value, String>, index: u32);
    impl_enum_method!(get_transactions,Result<Value, String>, details: Value);
    impl_enum_method!(get_transaction_details,Result<Value, String>, txid: String);
    impl_enum_method!(get_balance,Result<Value, String>, details: Value);
    impl_enum_method!(set_transaction_memo,Result<(), String>, txid: String, memo: String, memo_type: u32);
    impl_enum_method!(create_transaction,Result<String, String>, details: Value);
    impl_mut_enum_method!(sign_transaction,Result<Value, String>, tx_detail_unsigned: Value);
    impl_enum_method!(send_transaction,Result<String, String>, tx_detail_signed: Value);
    impl_enum_method!(broadcast_transaction,Result<String, String>, tx_hex: String);
    impl_enum_method!(get_receive_address,Result<Value, String>, addr_details: Value);
    impl_enum_method!(get_mnemonic_passphrase,Result<String, String>, _password: String);
    impl_enum_method!(get_available_currencies,Result<Value, String>);
    impl_enum_method!(convert_amount,Result<Value, String>, value_details: Value);
    impl_enum_method!(get_fee_estimates,Result<Value, String>);
    impl_enum_method!(get_settings,Result<Value, String>);
    impl_mut_enum_method!(change_settings,Result<(), String>, settings: Value);
}

