use crate::utils;

use csv::ReaderBuilder;
use hex;
use utils::*;
use std::error::Error;
use std::collections::HashSet;
use std::convert::Infallible;
use warp::Filter;
use web3::types::H160;
use rusqlite::{params, Connection, Result};
use hex::encode;

pub const ALERT_LIST_URL: &str = "https://raw.githubusercontent.com/forta-network/starter-kits/1131fb4a3221c611d931c7b212fb6a4077934d6b/scam-detector-py/manual_alert_list.tsv";

pub struct ShieldState {
  pub  alert_list: Vec<H160>,
  pub  db: Connection,
}

impl ShieldState {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            alert_list: fetch_alert_list(ALERT_LIST_URL).await.unwrap(),
            db: get_db_conn(),
        })
    }

    pub fn init_db(&self)-> Result<(),String> {
        match initialize_tables(&self.db) {
            Ok(_) => println!("Tables created or already exist."),
            Err(e) => {
                    return Err(format!("Error initializing tables: {}", e)); 
            }
        }
        // fill db with addresses from external alert list
          match insert_addresses(&self.db, &self.alert_list.to_vec()) {
            Ok(_) => println!("Addresses inserted successfully."),
            Err(e) => {
                return Err(format!("Error inserting addresses: {}", e)); 
            }
        }
        Ok(())
    }
}

pub fn with_db() -> impl Filter<Extract = (Connection,), Error = Infallible> + Clone {
    warp::any().map(|| get_db_conn())
}

pub fn get_db_conn()->Connection{
    let conn = Connection::open("to_addresses.db").expect("Failed to open SQLite connection");
    conn
}

pub async  fn fetch_alert_list(url: &str) -> Result<Vec<H160>, Box<dyn Error>> {
    let response = reqwest::get(url).await?.bytes().await?;
    let text = String::from_utf8(response.to_vec())?;

    let mut alert_list = Vec::new();
    let mut rdr = ReaderBuilder::new()
        .delimiter(b'\t')
        .has_headers(true)
        .from_reader(text.as_bytes());

    let entity_index = match rdr.headers()?.iter().position(|h| h == "Entity") {
        Some(index) => index,
        None => {
            return Err("Column 'Entity' not found".into());
        }
    };

    for result in rdr.records() {
        let record = result?;
        if let Some(address) = record.get(entity_index) {
            // Trim any leading or trailing whitespace
            let trimmed_address = address.trim();

            if trimmed_address.is_empty() {
                // Skip empty addresses
                continue;
            }

            // Ensure the address starts with "0x"
            if !trimmed_address.starts_with("0x") {
                // Handle the error: Address doesn't start with "0x"
                eprintln!(
                    "Error: Address doesn't start with '0x': {}",
                    trimmed_address
                );
                continue;
            }

            if let Ok(bytes) = hex::decode(&trimmed_address[2..]) {
                let h160 = H160::from_slice(&bytes);
                alert_list.push(h160);
            } else {
                eprintln!(
                    "Error: Invalid hexadecimal format for address: {}",
                    trimmed_address
                );
            }
        }
    }

    Ok(alert_list)
}



pub fn insert_address(conn: &Connection, address: &str) -> Result<(), String> {
    let mut stmt = conn.prepare("INSERT OR IGNORE INTO cached_addresses (address) VALUES (?1)")
    .map_err(|e| format!("Failed to prepare statement: {}", e))?;

    let result = stmt.execute(params![address])
        .map_err(|e| format!("Failed to insert address {}: {}", address, e));

    if let Err(err) = result {
        return Err(err);
    }


    Ok(())
}



pub fn fetch_cached_addresses(conn: &Connection) -> Result<HashSet<H160>> {
    let mut stmt = conn.prepare("SELECT address FROM cached_addresses")?;
    let address_iter = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut cached_addresses = HashSet::new();
    for address in address_iter {
        match address {
            Ok(addr) => {        
                if let Ok(h160_address) = string_to_h160(&addr) {
                    cached_addresses.insert(h160_address);
                }else{
                    eprintln!("not ok addr: {}", addr);  
                }
            }
            Err(e) => {eprintln!("Error fetching cached: {}", e)}, 
        }
    }

    Ok(cached_addresses)
}

pub fn insert_addresses(conn: &Connection, addresses: &Vec<H160>) -> Result<(), String> {

    println!("Initializing malicious_addresses table with {} items", addresses.len());

    let mut stmt = conn.prepare("INSERT OR IGNORE INTO malicious_addresses (address) VALUES (?1)")
        .map_err(|e| format!("Failed to prepare statement: {}", e))?;

    for address in addresses {
        let result = stmt.execute(params![format!("0x{}", encode(address.as_bytes()))])
            .map_err(|e| format!("Failed to insert address {}: {}", address, e));

        if let Err(err) = result {
            return Err(err);
        }
    }

    // Return Ok if all addresses were successfully inserted
    Ok(())
}

pub fn initialize_tables(conn: &Connection) -> Result<(), String> {
    // Attempt to execute the SQL query to create the table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS malicious_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
  address CHAR(50) UNIQUE NOT NULL
        )",
        [], // No parameters for the query
    ).map_err(|e| {
        // Return a detailed error message if something goes wrong
        format!("Error creating table 'addresses': {}", e)
    })?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS cached_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
     address CHAR(50) UNIQUE NOT NULL
        )",
        [], // No parameters for the query
    ).map_err(|e| {
        // Return a detailed error message if something goes wrong
        format!("Error creating table 'addresses': {}", e)
    })?;

    Ok(())
}