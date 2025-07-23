# ISOserver.py
from flask import Flask, request, jsonify
import socket
import os
import json # Assuming your load_config is in a separate util
# from your_iso8583_library import pack_iso_message, unpack_iso_message # Placeholder

app = Flask(__name__)

# Internal server configuration
INTERNAL_HOST = '0.0.0.0'
INTERNAL_PORT = int(os.environ.get('PORT', 9000)) # Render assigns PORT, default for local

# External ISO8583 server details (PLACEHOLDERS!)
# These MUST be provided by Visa/Mastercard/Amex directly and secured.
VISA_MC_ISO_HOST = os.environ.get('VISA_MC_ISO_HOST', 'iso.example.com') # Example: 'test-iso.visa.com'
VISA_MC_ISO_PORT = int(os.environ.get('VISA_MC_ISO_PORT', 8583)) # Example: 8583

# --- Placeholder ISO8583 functions ---
# In a real scenario, this would be a robust library or your own detailed implementation.
def pack_iso_message(data):
    """
    Packs transaction data into an ISO8583 message.
    This is highly complex and specific to the card network's implementation.
    Returns bytes.
    """
    print(f"Packing ISO message with data: {data}")
    # Example: Build a simple MTI 0100 authorization request
    # This is a very simplistic placeholder; real ISO8583 packing is intricate.
    # It involves bitmaps, field encoding (ASCII, EBCDIC, BCD), length indicators, etc.
    mti = "0100"
    # Dummy fields for illustration
    pan = data.get("card_number", "")
    amount = f"{int(data.get('amount', 0) * 100):012d}" # Amount in cents, 12 digits
    proc_code = "000000" # Purchase
    tx_id = data.get("txn_id", "000000")
    
    # A real bitmap and data elements would be constructed here
    # For now, just a basic string simulation
    iso_string = f"{mti}{pan}{amount}{proc_code}{tx_id}"
    return iso_string.encode('ascii') # Use correct encoding for the actual gateway

def unpack_iso_message(iso_response_bytes):
    """
    Unpacks an ISO8583 response message.
    Returns status, response_code, transaction_id, message.
    """
    response_str = iso_response_bytes.decode('ascii') # Use correct encoding
    print(f"Unpacking ISO response: {response_str}")
    # This is a very simplistic placeholder.
    # Real unpacking involves parsing MTI, bitmap, and specific data elements.
    if "APPROVED" in response_str: # Simulating a simple "approved" message
        return "approved", "00", "RESP" + response_str[-6:], "Transaction Approved"
    elif "DECLINED" in response_str: # Simulating a simple "declined" message
        return "declined", "05", "RESP" + response_str[-6:], "Do Not Honor"
    else:
        return "declined", "XX", "UNKNOWN", "Unknown Response"


@app.route('/authorize', methods=['POST'])
# ROUTING URL: /authorize
# COMMAND: Receives HTTP POST with JSON payload from app.py
def authorize_transaction():
    data = request.json
    print(f"ISOserver: Received authorization request: {data}")

    # 1. Validate incoming data (Crucial for a real system!)
    if not all(k in data for k in ["card_number", "amount", "expiry", "cvv", "protocol"]):
        return jsonify({"status": "error", "message": "Missing required transaction data"}), 400

    # 2. Pack data into ISO8583 message
    try:
        iso_message = pack_iso_message(data)
    except Exception as e:
        print(f"ISOserver: Error packing ISO message: {e}")
        return jsonify({"status": "error", "message": f"Failed to pack ISO8583 message: {e}"}), 500

    # 3. Send to external Visa/MC ISO8583 server (via raw TCP/IP socket)
    response_iso_message = b"" # Initialize as bytes
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30) # Set a timeout for the external connection
            print(f"ISOserver: Connecting to external ISO host: {VISA_MC_ISO_HOST}:{VISA_MC_ISO_PORT}")
            s.connect((VISA_MC_ISO_HOST, VISA_MC_ISO_PORT))
            print(f"ISOserver: Sending {len(iso_message)} bytes to external ISO host.")
            s.sendall(iso_message)
            # A real ISO8583 server might send a length prefix first, then the message.
            # You might need to read the length prefix, then read that many bytes.
            response_iso_message = s.recv(4096) # Read up to 4096 bytes response
            print(f"ISOserver: Received {len(response_iso_message)} bytes response from external ISO host.")

    except socket.timeout:
        print("ISOserver: Timeout connecting/receiving from external ISO host.")
        return jsonify({"status": "error", "message": "External ISO server communication timed out"}), 504
    except socket.error as e:
        print(f"ISOserver: Socket error communicating with external ISO host: {e}")
        return jsonify({"status": "error", "message": f"ISO8583 network error: {e}"}), 500
    except Exception as e:
        print(f"ISOserver: Unexpected error during external ISO communication: {e}")
        return jsonify({"status": "error", "message": f"Unexpected error with external ISO: {e}"}), 500

    # 4. Unpack ISO8583 response
    try:
        auth_status, response_code, transaction_id_from_iso, message = unpack_iso_message(response_iso_message)
        if auth_status == "approved":
            return jsonify({
                "status": "approved",
                "message": message,
                "transaction_id": transaction_id_from_iso, # Use ID returned by ISO
                "response_code": response_code
            })
        else:
            return jsonify({
                "status": "declined",
                "message": message,
                "transaction_id": transaction_id_from_iso,
                "response_code": response_code
            })
    except Exception as e:
        print(f"ISOserver: Error unpacking ISO message: {e}")
        return jsonify({"status": "error", "message": f"Failed to unpack ISO8583 response: {e}"}), 500

if __name__ == '__main__':
    print(f"ISOserver running on {INTERNAL_HOST}:{INTERNAL_PORT}")
    app.run(host=INTERNAL_HOST, port=INTERNAL_PORT, debug=True) # debug=True only for dev
