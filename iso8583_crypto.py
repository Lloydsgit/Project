import socket
import json
import os
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey
from decimal import Decimal
from datetime import datetime

CONFIG_PATH = 'config.json'

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

config = load_config()

def send_iso8583_transaction(message_str):
    """Sends a pure string-based ISO8583 message over TCP to the test server and gets response."""
    HOST = config["iso8583"]["host"]
    PORT = config["iso8583"]["port"]
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(message_str.encode())
        data = s.recv(2048)
        return data.decode()

def send_erc20_payout(to_address, amount_usdt):
    """Send USDT ERC20 payout"""
    if not Web3.is_address(to_address):
        raise ValueError("Invalid Ethereum address")

    network = config["erc20"]["network"]
    rpc_url = config["erc20"]["mainnet_rpc"] if network == "mainnet" else config["erc20"]["testnet_rpc"]
    private_key = config["erc20"]["private_key"]
    usdt_contract = config["erc20"]["usdt_contract"]
    gas_price_gwei = config["erc20"].get("gas_price_gwei", 15)

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    account = w3.eth.account.from_key(private_key)
    from_addr = account.address

    nonce = w3.eth.get_transaction_count(from_addr)
    decimals = 6
    value = int(amount_usdt * (10 ** decimals))

    abi = [
        {
            "constant": False,
            "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
            "name": "transfer",
            "outputs": [{"name": "success", "type": "bool"}],
            "type": "function"
        }
    ]
    contract = w3.eth.contract(address=Web3.to_checksum_address(usdt_contract), abi=abi)
    tx = contract.functions.transfer(to_address, value).build_transaction({
        'chainId': 1 if network == 'mainnet' else 5,
        'gas': 100000,
        'gasPrice': w3.to_wei(gas_price_gwei, 'gwei'),
        'nonce': nonce,
    })

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    return w3.to_hex(tx_hash)

def send_trc20_payout(to_address, amount_usdt):
    """Send USDT TRC20 payout"""
    client = Tron(network=config["trc20"]["network"])
    private_key = PrivateKey(bytes.fromhex(config["trc20"]["private_key"]))
    from_addr = private_key.public_key.to_base58check_address()
    usdt_contract = config["trc20"]["usdt_contract"]

    contract = client.get_contract(usdt_contract)
    txn = (
        contract.functions.transfer(to_address, int(amount_usdt * 1_000_000))
        .with_owner(from_addr)
        .fee_limit(5_000_000)
        .build()
        .sign(private_key)
        .broadcast()
    )
    return txn['txid']
