
use std::collections::HashSet;
use web3::types::H160;
use rusqlite::{params, Connection, Result};
use hex::encode;


pub fn is_malicious_address(conn: &Connection, address: H160) -> Result<bool> {

    let mut stmt = conn.prepare("SELECT COUNT(*) FROM malicious_addresses WHERE address = ?1")?;
    
    let count: i64 = stmt.query_row(params![format!("0x{}", encode(address.as_bytes()))], |row| row.get(0))?;
    

    Ok(count > 0)
}

pub fn is_vanity_address(address: &H160, cached_addresses: &HashSet<H160>) -> bool {
    let address_str = format!("{:x}", address); 

    for tolerance in 1..=12 {
        for cached in cached_addresses {
     
            let cached_str = format!("{:x}", cached);

            if cached_str != address_str && cached_str.len() > tolerance && address_str.len() > tolerance {
                let cached_prefix = &cached_str[..tolerance];
                let address_prefix = &address_str[..tolerance];
                let cached_suffix = &cached_str[cached_str.len() - tolerance..];
                let address_suffix = &address_str[address_str.len() - tolerance..];

                
                if cached_prefix == address_prefix && cached_suffix == address_suffix {
                    return true; 
                }
            }
        }
    }

    false 
}