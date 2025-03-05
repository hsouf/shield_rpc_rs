use web3::types::H160;
pub fn option_string_to_h160(opt_string: Option<String>) -> Option<H160> {
    opt_string.map(|s| {
        // Parse the string as H160
        H160::from_slice(&hex::decode(&s).unwrap_or_default())
    })
}

pub fn option_to_string(option: Option<String>) -> String {
    option.unwrap_or("default string".to_string())
}