use serde::Serialize;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: i32,
    pub method: String,
    pub params: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse<'a> {
    pub id: i8,
    pub jsonrpc: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}
impl<'a> RpcResponse<'a> {
    // Constructor to create a new RpcResponse with default values
    pub fn new(result: Option<&'a str>, error: Option<RpcError>) -> Self {
        RpcResponse {
            id: 2,
            jsonrpc: "2.0",
            result,
            error,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RpcErrorCode {
    InvalidRequest,
    InvalidParams,
}

impl RpcErrorCode {
    pub fn to_error_code(&self) -> i32 {
        match self {
            RpcErrorCode::InvalidRequest => -32600,
            RpcErrorCode::InvalidParams => -32602,
        }
    }
}

