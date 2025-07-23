import socket
import os
import json
import random

# This file is a MODULE, designed to be imported by app.py.
# It contains functions for ISO8583 message handling and external communication.
# It is NOT a standalone Flask application.

# External ISO8583 server details (PLACEHOLDERS!)
# These should ideally come from environment variables in app.py and be passed to these functions.
# For now, we'll use dummy defaults for standalone testing.
DEFAULT_VISA_MC_ISO_HOST = os.environ.get('VISA_MC_ISO_HOST', 'iso.example.com') # Example: 'test-iso.visa.com'
DEFAULT_VISA_MC_ISO_PORT = int(os.environ.get('VISA_MC_ISO_PORT', 8583)) # Example: 8583

def load_config():
    """
    Dummy function to load configuration relevant to ISO8583.
    In a real scenario, this would load sensitive config securely.
    """
    print("ISO8583_Server Module: DUMMY: Loading configuration...")
    return {
        "iso_server_host": DEFAULT_VISA_MC_ISO_HOST,
        "iso_server_port": DEFAULT_VISA_MC_ISO_PORT,
        "dummy_iso_key": "dummy_iso_value" # Example dummy key
    }

def pack_iso_message(data):
    """
    DUMMY: Packs transaction data into a simulated ISO8583 message (bytes).
    This is highly simplified. In a real system, this would involve complex
    binary packing according to the ISO8583 standard and specific network requirements.
    """
    print(f"ISO8583_Server Module: DUMMY: Packing ISO message with data: {data}")
    mti = "0100" # Authorization Request (dummy)
    card_number = data.get("card_number", "").replace(" ", "")
    amount = f"{int(float(data.get('amount', 0)) * 100):012d}" # Amount in cents, 12 digits
    txn_id = data.get("txn_id", "000000")
    auth_code = data.get("auth_code", "000000")

    # A very basic, non-compliant string representation for simulation
    iso_string = f"{mti}|{card_number}|{amount}|{txn_id}|{auth_code}"
    
    # Prepend a 2-byte length header (common in ISO8583)
    msg_len = len(iso_string)
    length_header = msg_len.to_bytes(2, 'big') # 2-byte big-endian length
    
    return length_header + iso_string.encode('ascii') # Use correct encoding for the actual gateway

def unpack_iso_message(iso_response_bytes):
    """
    DUMMY: Unpacks a simulated ISO8583 response message.
    In a real system, this would involve parsing the binary ISO8583 response
    based on MTI, bitmaps, and data element definitions.
    """
    if not iso_response_bytes:
        return "declined", "99", "UNKNOWN", "No response from ISO host"

    try:
        # Assume the first 2 bytes are length, then the message content
        msg_len = int.from_bytes(iso_response_bytes[:2], 'big')
        response_str = iso_response_bytes[2:].decode('ascii')
    except Exception as e:
        print(f"ISO8583_Server Module: DUMMY: Error parsing response length or decoding: {e}")
        return "declined", "XX", "UNKNOWN", "Invalid ISO response format"

    print(f"ISO8583_Server Module: DUMMY: Unpacking ISO response: {response_str}")

    # Simulate parsing based on a simple string content for dummy responses
    if "APPROVED" in response_str:
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

def send_iso8583_transaction(session_data, iso_host, iso_port):
    """
    Sends an ISO8583 transaction to the external host.
    This function is called directly by app.py.
    """
    print(f"ISO8583_Server Module: Initiating ISO8583 transaction for TXN ID: {session_data.get('txn_id')}")

    try:
        iso_message_bytes = pack_iso_message(session_data)
    except Exception as e:
        raise ValueError(f"Failed to pack ISO8583 message: {e}")

    response_iso_message_bytes = b""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(30) # Set a timeout for the external connection
            print(f"ISO8583_Server Module: Connecting to external ISO host: {iso_host}:{iso_port}")
            # This is where the actual connection to a real ISO8583 gateway would happen.
            # For a dummy test, you might point this to a local mock server or a service
            # that simply returns a hardcoded response.
            s.connect((iso_host, iso_port)) 
            print(f"ISO8583_Server Module: Sending {len(iso_message_bytes)} bytes to external ISO host.")
            s.sendall(iso_message_bytes)
            response_iso_message_bytes = s.recv(4096) # Read response from the socket
            print(f"ISO8583_Server Module: Received {len(response_iso_message_bytes)} bytes response from external ISO host.")

    except socket.timeout:
        # Raise a specific error for timeout
        raise ConnectionError("External ISO server communication timed out")
    except socket.error as e:
        # Raise a specific error for socket issues (e.g., connection refused, host not found)
        raise ConnectionError(f"ISO8583 network error: {e}")
    except Exception as e:
        # Catch any other unexpected errors during communication
        raise Exception(f"Unexpected error with external ISO communication: {e}")

    # Unpack the received ISO8583 response
    auth_status, response_code, transaction_id_from_iso, message = unpack_iso_message(response_iso_message_bytes)
    
    # Return a dictionary with the parsed results
    return {
        "status": auth_status,
        "message": message,
        "transaction_id": transaction_id_from_iso,
        "response_code": response_code
    }

# This `if __name__ == "__main__":` block is for testing this module independently.
# It will NOT run when this file is imported by app.py.
if __name__ == "__main__":
    print("Running ISO8583_Server Module in standalone test mode.")
    dummy_session_data = {
        'txn_id': 'TEST_TXN_001',
        'pan': '4111222233334444',
        'amount': 123.45,
        'auth_code': '654321',
        'expiry': '1225',
        'cvv': '123',
        'protocol': 'POS-101.1'
    }
    try:
        # For testing, you might need a local mock ISO server running on DEFAULT_VISA_MC_ISO_PORT
        # or change the host/port to a known test endpoint.
        print(f"Attempting to send dummy transaction to {DEFAULT_VISA_MC_ISO_HOST}:{DEFAULT_VISA_MC_ISO_PORT}")
        result = send_iso8583_transaction(dummy_session_data, DEFAULT_VISA_MC_ISO_HOST, DEFAULT_VISA_MC_ISO_PORT)
        print(f"\nTest ISO Transaction Result: {result}")
    except Exception as e:
        print(f"\nTest ISO Transaction Failed: {e}")
