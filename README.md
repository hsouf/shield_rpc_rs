## SHIELD RPC
A proxy on top of your node RPC to block any interaction with fraudulent contracts/wallets.

### How does it work?

Getting started is simple! Add your preferred RPC URL as a query parameter, start your server, and you're all set. Any transactions —whether sending or calling—that involve a suspicious address will be blocked immediately.

Types of addresses that should be blocked:
- Vanity Addresses: The shield maintains a record of all legitimate wallets and contracts you've previously interacted with. It can detect and block future interactions with any potential vanity addresses that deviate from your trusted address list. So the next time you send a couple of ETH to your pal's wallet, it will be marked as trusted. However, if a few days later you attempt to send funds to a wallet that resembles your friend's—such as a vanity address with at least similar first and last bytes—it will be flagged and blocked by the Shield RPC. If needed, you can still force-push the transaction with user authorization, which can be seamlessly implemented using a frontend.

 
- Right now for the POC I'm using the alert list genereously put together [here](https://github.com/forta-network/starter-kits/blob/1131fb4a3221c611d931c7b212fb6a4077934d6b/scam-detector-py/manual_alert_list.tsv#L177) by Certik, AegisWeb3, Peckshield, Blocksec...



### Running locally

Build the Rust Project:
``````
Cargo build
``````

Run project 
`````
cargo run
`````
Start proxy:

```
http://localhost:3030/shield?rpc=YOUR_PRIVATE_RPC
``````

## TO DO

- [x] Prevent address poisoning attacks by blocking any interaction with vanity addresses.
- [ ] Add a configurable wait time for txs before they get forwarded in case you changed your mind at the last minute (just like emails but better)
- [ ] Real-time update of the alert list

