import sqlite3

conn = sqlite3.connect("moonvest.db")

# Add columns to users table (run only once)
try:
    conn.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0;")
except Exception as e:
    print("balance column may already exist:", e)

try:
    conn.execute("ALTER TABLE users ADD COLUMN portfolio_growth REAL DEFAULT 0;")
except Exception as e:
    print("portfolio_growth column may already exist:", e)

# Create transactions table
conn.execute("""
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,
    type TEXT,
    amount REAL,
    status TEXT,
    created_at TEXT
);
""")

conn.commit()
conn.close()
print("Database updated!")