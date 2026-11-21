"""Exercise the real SQL lab route against an isolated temporary SQLite DB."""
import argparse
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-vulnerable", action="store_true")
    args = parser.parse_args()
    module_path = ROOT / "dockerized_labs/sql_injection_lab/app.py"
    spec = importlib.util.spec_from_file_location("sql_lab", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    original_cwd = Path.cwd()
    try:
        with tempfile.TemporaryDirectory(prefix="lab5-sql-") as temporary:
            os.chdir(temporary)
            with closing(sqlite3.connect("database.db")) as connection:
                connection.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT NOT NULL)")
                connection.execute("INSERT INTO users VALUES (?, ?)", ("admin", "lab-test-password"))
                connection.commit()
            with module.app.test_client() as client:
                valid = client.post("/lab", data={"username": "admin", "password": "lab-test-password"})
                invalid = client.post("/lab", data={"username": "admin", "password": "wrong"})
                injected = client.post("/lab", data={"username": "admin' -- ", "password": "wrong"})
                apostrophe = None if args.expect_vulnerable else client.post(
                    "/lab", data={"username": "O'Brien", "password": "wrong"})
            os.chdir(original_cwd)
            assert valid.status_code == 200 and b"Logged in as:" in valid.data
            assert invalid.status_code == 200 and b"Invalid username or password" in invalid.data
            bypass = b"Logged in as:" in injected.data
            assert bypass == args.expect_vulnerable, "SQL injection behavior differs from expected state"
            if not args.expect_vulnerable:
                assert b"Invalid username or password" in injected.data
                assert b"Invalid username or password" in apostrophe.data
            print(json.dumps({
                "source": str(module_path.relative_to(ROOT)),
                "expected_state": "vulnerable" if args.expect_vulnerable else "patched",
                "valid_login_succeeds": True,
                "incorrect_password_rejected": True,
                "sql_injection_bypasses_login": bypass,
                "apostrophe_handled_as_data": None if apostrophe is None else b"Invalid username or password" in apostrophe.data,
                "result": "PASS",
            }, indent=2))
    finally:
        os.chdir(original_cwd)


if __name__ == "__main__":
    main()
