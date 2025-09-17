from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from functools import wraps
import os, sqlite3, re, datetime as dt
from werkzeug.security import generate_password_hash, check_password_hash

# Firebase Admin SDK
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
import os
import json

# ---------- Secure Firebase Init ----------
if not firebase_admin._apps:
    if os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON"):
        firebase_creds = json.loads(os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON"))
        cred = credentials.Certificate(firebase_creds)
        firebase_admin.initialize_app(cred)
    else:
        # Fallback for local dev (using serviceAccountKey.json)
        cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
# ------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
DB_PATH = os.path.join(os.path.dirname(__file__), "moonvest.db")
# ---------- Transactions DB (SQLite) ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            type TEXT,
            amount REAL,
            status TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()
init_db()

def add_transaction(user_email, tx_type, amount, status="Completed"):
    conn = get_db()
    conn.execute(
        "INSERT INTO transactions (user_email, type, amount, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_email, tx_type, amount, status, dt.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

@app.context_processor
def inject_globals():
    return dict(USER=session.get("user"), BRAND="Legacy Wealth Solution")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
def valid_email(email): return bool(EMAIL_RE.match(email or ""))
def password_ok(pw):   return isinstance(pw, str) and len(pw) >= 6

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            nxt = request.path if request.method == "GET" else url_for("dashboard")
            return redirect(url_for("login", next=nxt))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapped

# ---------- Firebase Session Login ----------
@app.route("/sessionLogin", methods=["POST"])
def session_login():
    id_token = request.json.get("idToken")
    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        email = decoded_token["email"]
        name = decoded_token.get("name", email.split("@")[0])

        # Check Firestore for admin role
        db = firestore.client()
        user_doc = db.collection('users').document(email).get()
        if user_doc.exists and user_doc.to_dict().get('role') == 'admin':
            session["admin"] = True
            session["user"] = {"email": email, "name": name}
            return jsonify({"status": "success", "redirect": url_for("admin_users")})
        else:
            session["user"] = {"email": email, "name": name}
            session.pop("admin", None)
            return jsonify({"status": "success", "redirect": url_for("dashboard")})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 401

# ---------- Public ----------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm  = request.form.get("confirm")  or ""

        errors = {}
        if not name: errors["name"] = "Please enter your full name."
        if not valid_email(email): errors["email"] = "Enter a valid email."
        if not password_ok(password): errors["password"] = "Min 6 characters."
        if password != confirm: errors["confirm"] = "Passwords do not match."

        if errors:
            return render_template("signup.html", error="Fix the errors below.",
                                   errors=errors, form={"name": name, "email": email})

        db = firestore.client()
        user_doc = db.collection('users').document(email).get()
        if user_doc.exists:
            return render_template("signup.html",
                                   error="Email already registered.",
                                   errors={"email": "Email already registered."},
                                   form={"name": name, "email": email})

        try:
            db.collection('users').document(email).set({
                "email": email,
                "name": name,
                "created_at": dt.datetime.utcnow().isoformat(),
                "balance": 0,
                "portfolio_growth": 0,
                "role": "user",
                "password_hash": generate_password_hash(password)
            })
            print(f"User {email} added to Firestore.")
        except Exception as e:
            print("Error adding user to Firestore:", e)
            return render_template("signup.html", error="Could not register user. Please try again.")

        session["user"] = {"email": email, "name": name}
        return redirect(url_for("dashboard"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        nxt = request.args.get("next") or request.form.get("next") or url_for("dashboard")

        if not valid_email(email) or not password:
            return render_template("login.html", error="Invalid email or password.",
                                   form={"email": email}, next=nxt)

        db = firestore.client()
        user_doc = db.collection('users').document(email).get()
        user = user_doc.to_dict() if user_doc.exists else None

        if not user or not check_password_hash(user.get("password_hash", ""), password):
            return render_template("login.html", error="Invalid email or password.",
                                   form={"email": email}, next=nxt)

        session["user"] = {"email": user["email"], "name": user["name"]}
        session.pop("admin", None)
        if not nxt.startswith("/"):
            nxt = url_for("dashboard")
        return redirect(nxt)

    nxt = request.args.get("next", "")
    return render_template("login.html", next=nxt)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    print("Dashboard route started")  # Step 1
    user_email = session["user"]["email"]
    db = firestore.client()
    print("Firestore client created")  # Step 2
    user_doc = db.collection('users').document(user_email).get()
    print("User doc fetched")          # Step 3
    user_data = user_doc.to_dict() if user_doc.exists else {}
    print("User data processed")       # Step 4

    balance = user_data.get("balance", 0)
    portfolio_growth = user_data.get("portfolio_growth", 0)
    has_deposited = balance > 0

    # Get recent transactions from SQLite
    conn = get_db()
    rows = conn.execute(
        "SELECT type, amount, status, created_at FROM transactions WHERE user_email=? ORDER BY created_at DESC LIMIT 5",
        (user_email,)
    ).fetchall()
    conn.close()
    activity = []
    for row in rows:
        activity.append({
            "icon": "+" if row["type"] == "Deposit" else "–" if row["type"] == "Withdrawal" else "→",
            "title": row["type"],
            "time": row["created_at"],
            "amount": row["amount"],
            "status": row["status"]
        })

    kpis = {
        "portfolio_value": balance,
        "available_balance": balance,
        "monthly_change": portfolio_growth,
        "change_amount": 0,
        "portfolio_change_pct": portfolio_growth,
        "portfolio_change_value": 0
    }
    tickers = ["BTC", "AAPL", "VNQ", "TSLA", "SPY"]
    print("Rendering dashboard")       # Step 5
    return render_template("dashboard.html", kpis=kpis, tickers=tickers, activity=activity, has_deposited=has_deposited, balance=balance)


@app.route("/portfolio")
@login_required
def portfolio():
    user_email = session["user"]["email"]
    db = firestore.client()
    user_doc = db.collection('users').document(user_email).get()
    user_data = user_doc.to_dict() if user_doc.exists else {}

    data = {
    "total_deposited": user_data.get("balance", 0),
    "current_value": user_data.get("balance", 0),
    "total_profit": user_data.get("portfolio_growth", 0),
    "roi": user_data.get("portfolio_growth", 0),
    "total_value": user_data.get("balance", 0),
    "gain_loss": user_data.get("portfolio_growth", 0),  # <-- Add this line
    "distribution": [
        {"label": "Stocks", "percent": 65, "color": "#6aa5ff"},
        {"label": "ETFs",   "percent": 25, "color": "#6cd9a7"},
        {"label": "Crypto", "percent": 10, "color": "#b28bff"},
    ],
    "bars": {"deposited": user_data.get("balance", 0), "current": user_data.get("balance", 0)},
    "holdings": user_data.get("holdings", [])
}
    return render_template("portfolio.html", data=data)

@app.route("/transactions")
@login_required
def transactions():
    return render_template("transactions.html")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/support")
def support():
    return render_template("support.html")

@app.route("/about")
def about():
    return render_template("about.html")

# ---------- Admin ----------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        # Optionally, you can use Firestore roles instead of hardcoded credentials
        ADMIN_EMAIL = "ahmedforex328@gmail.com"
        ADMIN_PASSWORD = "cchhiiddeerraa"
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session["admin"] = True
            session["user"] = {"email": email, "name": email.split("@")[0]}
            return redirect(url_for("admin_users"))
        else:
            return render_template("admin_login.html", error="Invalid admin credentials.")
    return render_template("admin_login.html")

# Delete user (from Firestore and Firebase Auth)
@app.route("/admin/delete_user/<email>", methods=["POST"])
@admin_required
def admin_delete_user(email):
    db = firestore.client()
    db.collection('users').document(email).delete()
    # Optionally delete from Firebase Auth as well
    try:
        user = firebase_auth.get_user_by_email(email)
        firebase_auth.delete_user(user.uid)
    except Exception:
        pass
    return jsonify({"status": "success"})

# Edit/Add money to user dashboard
@app.route("/admin/edit_balance/<email>", methods=["POST"])
@admin_required
def admin_edit_balance(email):
    new_balance = request.json.get("balance")
    db = firestore.client()
    user_doc = db.collection('users').document(email).get()
    old_balance = user_doc.to_dict().get("balance", 0) if user_doc.exists else 0

    db.collection('users').document(email).update({"balance": float(new_balance)})

    change = float(new_balance) - old_balance
    if change > 0:
        add_transaction(email, "Deposit", change, "Completed")
    elif change < 0:
        add_transaction(email, "Withdrawal", abs(change), "Completed")

    return jsonify({"status": "success"})

# Control deposit/withdrawal status (still uses SQLite)
@app.route("/admin/update_transaction/<int:tx_id>", methods=["POST"])
@admin_required
def admin_update_transaction(tx_id):
    new_status = request.json.get("status")
    conn = get_db()
    conn.execute("UPDATE transactions SET status = ? WHERE id = ?", (new_status, tx_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

# Control portfolio growth
@app.route("/admin/edit_portfolio/<email>", methods=["POST"])
@admin_required
def admin_edit_portfolio(email):
    new_growth = request.json.get("growth")
    db = firestore.client()
    db.collection('users').document(email).update({"portfolio_growth": float(new_growth)})
    return jsonify({"status": "success"})

@app.route("/admin/transactions")
@admin_required
def admin_transactions():
    conn = get_db()
    transactions = conn.execute("SELECT * FROM transactions ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("admin_transactions.html", transactions=transactions)

@app.route("/admin/users")
@admin_required
def admin_users():
    db = firestore.client()
    users_ref = db.collection('users').stream()
    users = []
    for doc in users_ref:
        user = doc.to_dict()
        user['email'] = doc.id
        users.append(user)
    print("Fetched users:", users)
    return render_template("admin_users.html", users=users)

@app.route("/deposit", methods=["POST"])
@login_required
def deposit():
    user_email = session["user"]["email"]
    deposit_amount = float(request.form.get("amount"))
    db = firestore.client()
    db.collection('users').document(user_email).update({
        "balance": firestore.Increment(deposit_amount)
    })
    add_transaction(user_email, "Deposit", deposit_amount, "Completed")
    return redirect(url_for("dashboard"))

@app.route("/withdraw")
@login_required
def withdraw():
    return render_template("withdraw.html")

if __name__ == "__main__":
    app.run(debug=True)