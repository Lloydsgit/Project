from flask import Flask, request, jsonify
import os
import hashlib
import random # For dummy tx_hash generation

# This file is designed to run as a separate service.
# It handles the crypto payout logic.

app = Flask(__name__)

# Internal server configuration for this service
INTERNAL_HOST = '0.0.0.0'
INTERNAL_PORT = int(os.environ.get('PORT', 9001)) # Default to 9001 for local development

# Crypto API Keys (PLACEHOLDERS! Use environment variables!)
CRYPTO_API_KEY = os.environ.get('CRYPTO_API_KEY', 'your_crypto_api_key')
CRYPTO_SECRET = os.environ.get('CRYPTO_SECRET', 'your_crypto_secret')

# --- Placeholder Crypto functions ---
# In a real scenario, this would involve integrating with a crypto exchange API
# (e.g., Binance, Coinbase) or a web3 library for direct blockchain interaction.
def convert_fiat_to_crypto(amount_fiat, fiat_currency, crypto_currency_target):
    """
    DUMMY: Simulates converting fiat to crypto.
    Returns the equivalent crypto amount.
    """
    print(f"CryptoService: DUMMY: Converting {amount_fiat} {fiat_currency} to {crypto_currency_target}...")
    # This is a dummy conversion. Real-world rates vary.
    if crypto_currency_target == "USDT":
        return amount_fiat * 0.98 # Simulate a slight fee/spread
    elif crypto_currency_target == "ETH":
        return amount_fiat * 0.0003
    return amount_fiat # Fallback
    
def send_crypto_to_wallet(wallet_address, crypto_amount, crypto_currency):
    """
    DUMMY: Simulates sending crypto to a wallet.
    Returns a dummy transaction hash.
    """
    print(f"CryptoService: DUMMY: Sending {crypto_amount} {crypto_currency} to {wallet_address}...")
    # This is where your actual API calls to a crypto exchange or web3.py would go.
    # You'd manage gas fees, network selection (ERC20 vs TRC20), etc.
    if crypto_currency == "ERC20" and not wallet_address.startswith("0x"):
        raise ValueError("Invalid ERC20 wallet address format (must start with 0x)")
    if crypto_currency == "TRC20" and not wallet_address.startswith("T"):
        raise ValueError("Invalid TRC20 wallet address format (must start with T)")
    
    # Simulate success with a random hash
    tx_hash = hashlib.sha256(f"{wallet_address}{crypto_amount}{crypto_currency}{random.random()}".encode()).hexdigest()
    return f"0x{tx_hash}"[:66] # Ethereum-like hash format (66 chars including 0x)

@app.route('/payout', methods=['POST'])
# This is the API endpoint that app.py will call via HTTP POST.
def handle_payout():
    """
    Receives payout request from app.py, performs crypto conversion/transfer,
    and returns payout status.
    """
    data = request.json
    print(f"CryptoService: Received payout request from app.py: {data}")

    transaction_id = data.get("transaction_id")
    amount = data.get("amount")
    currency = data.get("currency")
    payout_type = data.get("payout_type") # e.g., 'ERC20', 'TRC20'
    merchant_wallet = data.get("merchant_wallet")

    if not all([transaction_id, amount, currency, payout_type, merchant_wallet]):
        print("CryptoService: Missing required payout data.")
        return jsonify({"status": "failed", "message": "Missing required payout data"}), 400

    try:
        # Determine target crypto currency (e.g., USDT on ERC20/TRC20)
        # This mapping might be more complex in a real system.
        # For simplicity, we assume 'amount' is already the crypto equivalent.
        # If 'amount' is fiat, you'd use convert_fiat_to_crypto here.
        crypto_amount_to_send = float(amount)

        # Send crypto to wallet
        tx_hash = send_crypto_to_wallet(merchant_wallet, crypto_amount_to_send, payout_type)

        return jsonify({"status": "success", "message": "Payout initiated", "tx_hash": tx_hash})
    except ValueError as e: # Catch validation errors from send_crypto_to_wallet
        print(f"CryptoService: Wallet address validation error: {e}")
        return jsonify({"status": "failed", "message": f"Invalid wallet or currency: {e}"}), 400
    except Exception as e:
        print(f"CryptoService: Payout error: {e}")
        return jsonify({"status": "failed", "message": f"Payout failed: {e}"}), 500

if __name__ == '__main__':
    print(f"Starting Crypto Payout Service on {INTERNAL_HOST}:{INTERNAL_PORT}")
    app.run(host=INTERNAL_HOST, port=INTERNAL_PORT, debug=True) # Set debug=False for production!
