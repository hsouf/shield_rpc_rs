mod types;
mod utils;

use csv::ReaderBuilder;
use hex;

use reqwest::{Client, Url};
use serde_json::Value;
use std::sync::{RwLock,Arc};
use std::{error::Error, str::FromStr};
use types::{JsonRpcRequest, RpcError, RpcErrorCode, RpcResponse};
use utils::{option_string_to_h160};
use std::collections::HashSet;
use std::convert::Infallible;
use warp::{Filter, Reply, Rejection};
use web3::types::H160;
use rusqlite::{params, Connection, Result};
use serde::Deserialize;

use ethers::types::{Transaction, H256};

const ALERT_LIST_URL: &str = "https://raw.githubusercontent.com/forta-network/starter-kits/1131fb4a3221c611d931c7b212fb6a4077934d6b/scam-detector-py/manual_alert_list.tsv";


fn string_to_h160(address_str: &str) -> Result<H160, String> {
    // Ensure the address is valid and properly formatted
    // We expect the address to start with "0x" and have 40 characters after it
    let full_address = address_str.trim(); // Remove any leading/trailing spaces
    if !full_address.starts_with("0x") || full_address.len() != 42 {
        return Err(format!("Invalid Ethereum address: {}", address_str));
    }

    // Now convert it to H160, ignoring the "0x" prefix
    H160::from_str(&full_address[2..]).map_err(|_| format!("Failed to convert address '{}'", full_address))
}

#[tokio::main]
async fn main() {
    // Initialize shared state
    let state = match AppState::new().await {
        Ok(state) => Arc::new(state),
        Err(e) => {
            eprintln!("Failed to initialize application: {}", e);
            return;
        }
    };
    let conn=get_db_conn();



  match create_table_if_not_exists(&conn) {
        Ok(_) => println!("Table created or already exists."),
        Err(e) => eprintln!("Error: {}", e), // Print error message if table creation fails
    }

      match insert_addresses(&conn, state.alert_list.to_vec()) {
        Ok(_) => println!("Addresses inserted successfully."),
        Err(e) => eprintln!("Error inserting addresses: {}", e),
    }


   
    // Define the route
    let shield_route = warp::path("shield")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::query::<QueryParams>())
        .and( with_db() )
        .and_then(handle_shield_request);
      

    // Start server
    warp::serve(shield_route)
        .run(([127, 0, 0, 1], 3030))
        .await;
}


pub fn create_table_if_not_exists(conn: &Connection) -> Result<(), String> {
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


fn with_db() -> impl Filter<Extract = (Connection,), Error = Infallible> + Clone {
    warp::any().map(|| get_db_conn())
}



pub fn get_db_conn()->Connection{
    let conn = Connection::open("to_addresses.db").expect("Failed to open SQLite connection");
    conn
}





async fn handle_shield_request(
    request: JsonRpcRequest,
    params: QueryParams,  
    conn: Connection,
) -> Result<impl Reply, Rejection>{
    let target = params.target
        .unwrap_or_else(|| "https://rpc-goerli.flashbots.net/fast".to_string()); // use default rp if target not provided

    if Url::parse(&target).is_err() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Please provide a valid RPC URL"),
            warp::http::StatusCode::OK,
        ));
    }
    

    let reply = handle_rpc_request(&request, &target, conn).await;
    Ok(reply)
}

#[derive(Debug)]
struct ServerError;

impl warp::reject::Reject for ServerError {}

#[derive(Deserialize)]
struct QueryParams {
    target: Option<String>,
}
// Application state
struct AppState {
    alert_list: Arc<Vec<H160>>,
    db: Arc<RwLock<Connection>>,
}



impl AppState {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            alert_list: Arc::new(fetch_alert_list(ALERT_LIST_URL).await.unwrap()),
            db: Arc::new(RwLock::new(Connection::open_in_memory()?)),
        })
    }
}
pub fn insert_addresses(conn: &Connection, addresses: Vec<H160>) -> Result<(), String> {
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
// loads the suscpicious addresses list in memory
async fn fetch_alert_list(url: &str) -> Result<Vec<H160>, Box<dyn Error>> {
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
use ethers::utils::{ rlp};
use hex::encode;
async fn handle_eth_send_raw_transaction(
    req: &JsonRpcRequest,
    target_endpoint: &str,
    conn: Connection,
) -> warp::reply::WithStatus<warp::reply::Json> {
    let raw_tx = req.params.get(0).unwrap();
  //let tx = Transaction::from_str (&raw_tx);
    //let to_address = option_string_to_h160(tx.to).unwrap();

    let raw_tx_no_prefix = &raw_tx[2..];
    let rlp_data = hex::decode(raw_tx_no_prefix).unwrap();
    let tx: Transaction = rlp::decode(&rlp_data).unwrap();

   let to_address=tx.to.unwrap();
  



    // if malicious interaction return error and don't forward tx to target rpc
    let is_malicious= is_malicious_address( &conn, to_address).unwrap();

    if is_malicious{
        let response = RpcResponse::new(
            None,
            Some(RpcError {
                code: RpcErrorCode::InvalidRequest.to_error_code(),
                message: format!(
                    "Interaction with a suspicious contract. To Address: {:?}",
                    to_address
                ),
            }),
        );

        let json_response = warp::reply::json(&response);
        return warp::reply::with_status(json_response, warp::http::StatusCode::OK);
    } 

    // check to address agains known addresses for any vanity address


    let cached_addresses = match fetch_cached_addresses(&conn) {
        Ok(addresses) => addresses,
        Err(e) => {
            eprintln!("Error fetching cached addresses: {}", e);
            HashSet::new()
        }
    };

   
        
    

  
   if is_vanity_address(&to_address, &cached_addresses) {
        let response = RpcResponse::new(
            None,
            Some(RpcError {
                code: RpcErrorCode::InvalidRequest.to_error_code(),
                message: format!(
                    "Interaction with a vanity address. To Address: {:?}",
                    to_address
                ),
            }),
        );

        let json_response = warp::reply::json(&response);
        return warp::reply::with_status(json_response, warp::http::StatusCode::OK);

    } 

    // cache address if all ok
    match insert_address(&conn, &format!("0x{}", encode(to_address.as_bytes())))
        {
            Ok(_) => println!("cached new address"),
            Err(e) => eprintln!("Error: {}", e), // Print error message if table creation fails
        }
    


    // if not malicious then proxy to target rpc
    let response = forward_request_to_target_rpc(&req, target_endpoint).await;
    let json_response;
    match response {
        Ok(res) => {
            json_response = warp::reply::json(&res);
        }
        Err(err) => {
            json_response = warp::reply::json(&format!("Error: {}", err));
        }
    }

    return warp::reply::with_status(json_response, warp::http::StatusCode::OK);
}

async fn handle_rpc_request(
    req: &JsonRpcRequest,
    target_endpoint: &str,
    conn: Connection,
) -> warp::reply::WithStatus<warp::reply::Json> {
    // catch raw txs
    if req.method == "eth_sendRawTransaction" {
        return handle_eth_send_raw_transaction(req, target_endpoint, conn).await;
    }
    // default other calls to target rpc
    let response = forward_request_to_target_rpc(req, target_endpoint).await;
    let json_response;
    match response {
        Ok(res) => {
            json_response = warp::reply::json(&res);
        }
        Err(err) => {
            json_response = warp::reply::json(&format!("Error: {}", err));
        }
    }

    return warp::reply::with_status(json_response, warp::http::StatusCode::OK);
}

async fn forward_request_to_target_rpc(
    req: &JsonRpcRequest,
    target_endpoint: &str,
) -> Result<Value, Box<dyn Error>> {
    let client = Client::new();
    let request_json = serde_json::to_value(&req).expect("Failed to serialize JSON request");
    let response = client
        .post(target_endpoint)
        .json(&request_json)
        .send()
        .await;

    match response {
        Ok(res) => {
            if res.status().is_success() {
                let json_response: Value = res.json().await.map_err(|err| {
                    println!("Failed to parse JSON response: {:?}", err);
                    err
                })?;
                Ok(json_response)
            } else {
                Err("RPC request failed".into()) 
            }
        }
        Err(err) => Err(err.into()),
    }
}








fn fetch_cached_addresses(conn: &Connection) -> Result<HashSet<H160>> {
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

fn init_db() -> Result<Connection> {
    let conn = Connection::open("to_addresses.db")?;

  
    conn.execute(
        "CREATE TABLE IF NOT EXISTS to_addresses (
            id INTEGER PRIMARY KEY,
        address CHAR(50) UNIQUE NOT NULL
        )",
        [],
    )?;

    Ok(conn)
}

fn is_vanity_address(address: &H160, cached_addresses: &HashSet<H160>) -> bool {
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

fn insert_address(conn: &Connection, address: &str) -> Result<(), String> {
 

    let mut stmt = conn.prepare("INSERT OR IGNORE INTO cached_addresses (address) VALUES (?1)")
    .map_err(|e| format!("Failed to prepare statement: {}", e))?;

eprintln!(" insert ====: {}", address);

    let result = stmt.execute(params![address])
        .map_err(|e| format!("Failed to insert address {}: {}", address, e));

    if let Err(err) = result {
        return Err(err);
    }


    Ok(())
}

pub fn is_malicious_address(conn: &Connection, address: H160) -> Result<bool> {

    let mut stmt = conn.prepare("SELECT COUNT(*) FROM malicious_addresses WHERE address = ?1")?;
    
    let count: i64 = stmt.query_row(params![format!("0x{}", encode(address.as_bytes()))], |row| row.get(0))?;
    

    Ok(count > 0)
}

