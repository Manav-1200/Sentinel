"""
Diagnoses why fetch_all() returned 0 samples: is the configured
db_path missing, empty, or pointing somewhere unexpected?
"""
import os
import sqlite3
import yaml

with open("config.yaml") as f:
    config = yaml.safe_load(f)

db_path = config["storage"]["db_path"]
print(f"config.yaml's storage.db_path resolves to: {db_path}")
print(f"Absolute path: {os.path.abspath(db_path)}")
print(f"File exists: {os.path.exists(db_path)}")

if os.path.exists(db_path):
    print(f"File size: {os.path.getsize(db_path)} bytes")
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        print(f"Tables in this DB: {tables}")
        if "labelled_flows" in tables:
            count = conn.execute("SELECT COUNT(*) FROM labelled_flows").fetchone()[0]
            print(f"Row count in labelled_flows: {count}")
    finally:
        conn.close()
else:
    print("The configured db_path does not exist on disk at all.")
    print("Searching for any .db files under the repo, in case the path in "
          "config.yaml is stale or the file lives elsewhere...")
    for root, dirs, files in os.walk("."):
        # skip virtualenvs / git internals for a cleaner result
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "venv", ".venv")]
        for f in files:
            if f.endswith(".db"):
                full = os.path.join(root, f)
                print(f"  Found: {full} ({os.path.getsize(full)} bytes)")