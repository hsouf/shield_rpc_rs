mod types;
mod utils;
mod state;
mod filters;
mod proxy;

use state::*;
use proxy::QueryParams;
use proxy::shield;
use warp::Filter;

// our defualt private rpc
pub const DEFAULT_RPC: &str ="https://rpc-goerli.flashbots.net/fast";


#[tokio::main]
async fn main() {

    let shield_state = match ShieldState::new().await {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to initialize application: {}", e);
            return;
        }
    };

    match shield_state.init_db(){
        Ok(_) => println!("shield db initialized successfully."),
        Err(e) => {
            eprintln!("failed to initialize application: {}", e);
            return;
        }
    }
    
    let shield_route = warp::path("shield")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::query::<QueryParams>())
        .and( with_db() )
        .and_then(shield);
      

    // start the server
    warp::serve(shield_route)
        .run(([127, 0, 0, 1], 3030))
        .await;
}



