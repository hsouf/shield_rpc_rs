
use crate::filters;
use crate::state;
use crate::types;
use crate::utils;

use reqwest::{Client, Url};
use serde_json::Value;
use std::error::Error;

use std::collections::HashSet;
use warp::{ Reply, Rejection};
use rusqlite::{ Connection, Result};
use serde::Deserialize;
use hex::encode;

use types::{JsonRpcRequest, RpcError, RpcErrorCode, RpcResponse};


pub const DEFAULT_RPC: &str ="https://rpc-goerli.flashbots.net/fast";




#[derive(Deserialize)]
pub struct QueryParams {
    pub rpc: Option<String>,
}

pub async fn shield(
    request: JsonRpcRequest,
    params: QueryParams,  
    conn: Connection,
) -> Result<impl Reply, Rejection>{
    let target = params.rpc
        .unwrap_or_else(|| DEFAULT_RPC.to_string()); // use default rp if target not provided

    if Url::parse(&target).is_err() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Please provide a valid RPC URL"),
            warp::http::StatusCode::OK,
        ));
    }

    let reply = handle_rpc_request(&request, &target, conn).await;
    Ok(reply)
}

async fn handle_eth_send_raw_transaction(
    req: &JsonRpcRequest,
    target_endpoint: &str,
    conn: Connection,
) -> warp::reply::WithStatus<warp::reply::Json> {
    let raw_tx = req.params.get(0).unwrap();
   let tx =utils::decode_transaction(raw_tx);
   let to_address=tx.to.unwrap();

    // if malicious interaction return error and don't forward tx to target rpc
    let is_malicious= filters::is_malicious_address( &conn, to_address).unwrap();

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
    let cached_addresses = match state::fetch_cached_addresses(&conn) {
        Ok(addresses) => addresses,
        Err(e) => {
            eprintln!("Error fetching cached addresses: {}", e);
            HashSet::new()
        }
    };

   if filters::is_vanity_address(&to_address, &cached_addresses) {
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
    match state::insert_address(&conn, &format!("0x{}", encode(to_address.as_bytes())))
        {
            Ok(_) => println!("cached new address {:}",format!("0x{}", encode(to_address.as_bytes())) ),
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


















