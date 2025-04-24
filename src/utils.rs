use web3::types::H160;
use ethers::utils::rlp;
use std::str::FromStr;
use ethers::types::Transaction;

pub fn string_to_h160(address_str: &str) -> Result<H160, String> {
    let full_address = address_str.trim(); 
    if !full_address.starts_with("0x") || full_address.len() != 42 {
        return Err(format!("Invalid Ethereum address: {}", address_str));
    }
    H160::from_str(&full_address[2..]).map_err(|_| format!("Failed to convert address '{}'", full_address))
}



pub fn decode_transaction(raw_tx: &str) -> Transaction {
    let raw_tx_no_prefix = &raw_tx[2..];  
    let rlp_data = hex::decode(raw_tx_no_prefix).unwrap(); 
    let tx: Transaction = rlp::decode(&rlp_data).unwrap(); 
    tx  
}