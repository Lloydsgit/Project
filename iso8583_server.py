from flask import Flask, request, jsonify
import socket
import os
import json # Assuming config.json is used by load_config

app = Flask(__name__)

# Internal server configuration for this service
# This service will listen on INTERNAL_HOST:INTERNAL_PORT for requests from app.py
INTERNAL_HOST = '0.0.0.0'
INTERNAL_PORT = int(os.environ.get('PORT', 9000)) # Default to 9000 for local development

# External ISO8583 server details (PLACEHOLDERS!)
# In a real scenario, these would be provided by Visa/Mastercard/Amex directly
# and stored securely as environment variables.
VISA_MC_ISO_HOST = os.environ.get('VISA_MC_ISO_HOST', 'iso.example.com') # e.g., 'test-iso.visa.com'
VISA_MC_ISO_PORT = int(os.environ.get('VISA_MC_ISO_PORT', 8583)) # e.g., 8583

# --- Placeholder ISO8583 functions ---
# These functions simulate the complex ISO8583 packing/unpacking and network communication.
# In a real system, you'd use a robust ISO8583 library (e.g., iso8583-parser)
# and handle cryptographic processes securely.

def load_config():
    """
    Dummy function to load configuration.
    In a real scenario, this would load sensitive config securely from a file or env.
    """
    print("ISOserver: DUMMY: Loading configuration...")
    # Return a dummy config dictionary
    return {
        "iso_server_host": VISA_MC_ISO_HOST,
        "iso_server_port": VISA_MC_ISO_PORT,
        "dummy_key": "dummy_value"
    }

def pack_iso_message(data):
    """
    DUMMY: Packs transaction data into a simulated ISO8583 message (bytes).
    This is highly simplified. Real ISO8583 packing is intricate, involving MTI,
    bitmaps, field encoding (ASCII, EBCDIC, BCD), length indicators, etc.
    """
    print(f"ISOserver: DUMMY: Packing ISO message with data: {data}")
    mti = "0100" # Authorization Request
    # Simulate some fields for the message
    card_number = data.get("card_number", "").replace(" ", "")
    amount = f"{int(float(data.get('amount', 0)) * 100):012d}" # Amount in cents, 12 digits
    txn_id = data.get("txn_id", "000000")
    auth_code = data.get("auth_code", "000000") # Authorization code from terminal

    # A very basic, non-compliant string representation
    iso_string = f"{mti}|{card_number}|{amount}|{txn_id}|{auth_code}"
    # Prepend a 2-byte length header (common in ISO8583)
    msg_len = len(iso_string)
    length_header = msg_len.to_bytes(2, 'big') # 2-byte big-endian length
    
    return length_header + iso_string.encode('ascii') # Use correct encoding for the actual gateway

def unpack_iso_message(iso_response_bytes):
    """
    DUMMY: Unpacks a simulated ISO8583 response message.
    Real unpacking involves parsing MTI, bitmap, and specific data elements.
    """
    if not iso_response_bytes:
        return "declined", "99", "UNKNOWN", "No response from ISO host"

    # Assume the first 2 bytes are length, then the message
    try:
        msg_len = int.from_bytes(iso_response_bytes[:2], 'big')
        response_str = iso_response_bytes[2:].decode('ascii')
    except Exception as e:
        print(f"ISOserver: DUMMY: Error parsing response length or decoding: {e}")
        return "declined", "XX", "UNKNOWN", "Invalid ISO response format"

    print(f"ISOserver: DUMMY: Unpacking ISO response: {response_str}")

    # Simulate parsing based on a simple string content
    if "APPROVED" in response_str:
        # Extract dummy transaction ID from the response string if available
        parts = response_str.split('|')
        tx_id = parts[3] if len(parts) > 3 else "RESP" + str(random.randint(1000, 9999))
        return "approved", "00", tx_id, "Transaction Approved"
    elif "DECLINED" in response_str:
        parts = response_str.split('|')
        response_code = parts[1] if len(parts) > 1 else "05" # Dummy decline code
        tx_id = parts[3] if len(parts) > 3 else "RESP" + str(random.randint(1000, 9999))
        return "declined", response_code, tx_id, f"Transaction Declined: {response_code}"
    else:
        return "declined", "XX", "UNKNOWN", "Unknown ISO Response"

# This function is not directly called by app.py via import,
# but its logic is encapsulated within the /authorize route.
# It's kept here for conceptual clarity if you were to refactor.
def _send_iso8583_transaction_logic(session_data):
    """Internal logic to send ISO8583 transaction, used by the /authorize endpoint."""
    # This is where the actual ISO8583 communication would happen.
    # For now, it's just a print statement.
    print(f"ISOserver: DUMMY: Executing _send_iso8583_transaction_logic for TXN ID: {session_data.get('txn_id')}")
    # Simulate a successful transaction
    session_data['field39'] = "00" # Dummy success code
    print("ISOserver: DUMMY: ISO8583 transaction logic simulated successfully.")


@app.route('/authorize', methods=['POST'])
# This is the API endpoint that app.py will call via HTTP POST.
def authorize_transaction():
    """
    Receives transaction data from app.py, packs it into ISO8583,
    sends to external ISO host, and returns authorization result.
    """
    data = request.json
    print(f"ISOserver: Received authorization request from app.py: {data}")

    # 1. Validate incoming data (Crucial for a real system!)
    required_fields = ["card_number", "amount", "expiry", "cvv", "protocol", "txn_id", "arn", "auth_code"]
    if not all(k in data for k in required_fields):
        missing_fields = [k for k in required_fields if k not in data]
        print(f"ISOserver: Missing required fields: {missing_fields}")
        return jsonify({"status": "error", "message": f"Missing required transaction data: {', '.join(missing_fields)}"}), 400

    # 2. Pack data into ISO8583 message
    try:
        iso_message_bytes = pack_iso_message(data)
    except Exception as e:
        print(f"ISOserver: Error packing ISO message: {e}")
        return jsonify({"status": "error", "message": f"Failed to pack ISO8583 message: {e}"}), 500

    # 3. Send to external Visa/MC ISO8583 server (via raw TCP/IP socket)
    response_iso_message_bytes = b""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30) # Set a timeout for the external connection
            print(f"ISOserver: Connecting to external ISO host: {VISA_MC_ISO_HOST}:{VISA_MC_ISO_PORT}")
            s.connect((VISA_MC_ISO_HOST, VISA_MC_ISO_PORT))
            print(f"ISOserver: Sending {len(iso_message_bytes)} bytes to external ISO host.")
            s.sendall(iso_message_bytes)
            response_iso_message_bytes = s.recv(4096) # Read response
            print(f"ISOserver: Received {len(response_iso_message_bytes)} bytes response from external ISO host.")

    except socket.timeout:
        print("ISOserver: Timeout connecting/receiving from external ISO host.")
        return jsonify({"status": "error", "message": "External ISO server communication timed out", "response_code": "504"}), 504
    except socket.error as e:
        print(f"ISOserver: Socket error communicating with external ISO host: {e}")
        return jsonify({"status": "error", "message": f"ISO8583 network error: {e}", "response_code": "500"}), 500
    except Exception as e:
        print(f"ISOserver: Unexpected error during external ISO communication: {e}")
        return jsonify({"status": "error", "message": f"Unexpected error with external ISO: {e}", "response_code": "999"}), 500

    # 4. Unpack ISO8583 response
    try:
        auth_status, response_code, transaction_id_from_iso, message = unpack_iso_message(response_iso_message_bytes)
        if auth_status == "approved":
            return jsonify({
                "status": "approved",
                "message": message,
                "transaction_id": transaction_id_from_iso,
                "response_code": response_code
            })
        else:
            return jsonify({
                "status": "declined",
                "message": message,
                "transaction_id": transaction_id_from_iso, # Still return if available
                "response_code": response_code
            })
    except Exception as e:
        print(f"ISOserver: Error unpacking ISO message: {e}")
        return jsonify({"status": "error", "message": f"Failed to unpack ISO8583 response: {e}", "response_code": "998"}), 500

if __name__ == '__main__':
    print(f"Starting ISOserver on {INTERNAL_HOST}:{INTERNAL_PORT}")
    app.run(host=INTERNAL_HOST, port=INTERNAL_PORT, debug=True) # Set debug=False for production!
