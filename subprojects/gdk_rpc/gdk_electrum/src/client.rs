use serde_json;

use std::{
    io::{self, Write, BufRead, BufReader},
    net::{TcpStream, ToSocketAddrs},
};
use serde::{Deserialize, Serialize};
use crate::tools;
use crate::error::WGError;

pub struct ElectrumxClient<A: ToSocketAddrs> {
    #[allow(dead_code)]
    socket_addr: A,
    stream: TcpStream,
}

#[derive(Debug, Deserialize)]
pub struct GetHistoryRes {
    pub height:  i32,
    pub tx_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct ListUnspentRes {
    pub height:  usize,
    pub tx_pos:  usize,
    pub value:  u64,
    pub tx_hash: String,
}

impl<A: ToSocketAddrs + Clone> ElectrumxClient<A> {
    pub fn new(socket_addr: A) -> io::Result<Self> {
        let stream = TcpStream::connect(socket_addr.clone())?;
        Ok(Self {
            socket_addr,
            stream,
        })
    }

    fn call(&mut self, req: Request) -> Result<(), WGError> {
        let raw = serde_json::to_vec(&req)?;
        self.stream.write_all(&raw)?;
        self.stream.write_all(&[10])?;
        self.stream.flush()?;
        Ok(())
    }

    fn recv(&self) -> io::Result<Vec<u8>> {
        let mut buff_stream = BufReader::new(&self.stream);
        let mut resp = Vec::new();
        buff_stream.read_until(10, &mut resp)?;
        Ok(resp)
    }

    pub fn estimate_fee(&mut self, number: usize) -> Result<f64, WGError> {
        let req = Request::new(0, "blockchain.estimatefee", vec![Param::Usize(number)]);
        self.call(req)?;
        let raw = self.recv()?;
        let resp: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(resp["result"].as_f64().unwrap())
    }

    pub fn blockchain_headers(&mut self) -> Result<serde_json::Value, WGError> {
        let req = Request::new(0, "blockchain.headers.subscribe", vec![]);
        self.call(req)?;
        let raw = self.recv()?;
        let value: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(value)
    }

    pub fn list_unspent(&mut self, addr: &str) -> Result<Vec<ListUnspentRes>, WGError> {
        let reversed = tools::decode_address_helper(&addr);
        let params = vec![Param::String(reversed)];
        let req = Request::new(0, "blockchain.scripthash.listunspent", params);
        self.call(req)?;
        let raw = self.recv()?;
        let resp: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(resp["result"].clone())?)
    }

    pub fn get_history(&mut self, addr: &str) -> Result<Vec<GetHistoryRes>, WGError> {
        let reversed = tools::decode_address_helper(&addr);
        let params = vec![Param::String(reversed)];
        let req = Request::new(0, "blockchain.scripthash.get_history", params);
        self.call(req)?;
        let raw = self.recv()?;
        let resp: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(serde_json::from_value(resp["result"].clone())?)
    }

    pub fn broadcast_transaction(&mut self, raw_tx: String) -> Result<String, WGError> {
        let params = vec![Param::String(raw_tx)];
        let req = Request::new(0, "blockchain.transaction.broadcast", params);
        self.call(req)?;
        let raw = self.recv()?;
        let resp: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(resp["result"].as_str().unwrap().to_string())
    }

    pub fn get_transaction(&mut self, tx_hash: String, verbose: bool) -> Result<String, WGError> {
        let params = vec![
            Param::String(tx_hash),
            Param::Bool(verbose),
        ];
        let req = Request::new(0, "blockchain.transaction.get", params);
        self.call(req)?;
        let raw = self.recv()?;
        let resp: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(resp["result"].as_str().unwrap().to_string())
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum Param {
    Usize(usize),
    String(String),
    Bool(bool),
}

#[derive(Serialize)]
struct Request<'a> {
    id: usize,
    method: &'a str,
    params: Vec<Param>,
}

impl<'a> Request<'a> {
    fn new(id: usize, method: &'a str, params: Vec<Param>) -> Self {
        Self {
            id,
            method,
            params,
        }
    }
}
