"""Utility script to create or update a manager account in the risto_db database.

Usage (examples):
    python create_admin.py --email admin@risto-solution.ch --password StrongPass! \
        --first-name Admin --last-name User --avs-number CH-ADMIN-001

The script uses the same defaults as the Flask app:
- host: DB_HOST (default: localhost)
- port: DB_PORT (default: 3306)
- user: DB_USER (default: root)
- password: DB_PASSWORD (default: chcAdmin)
- database: DB_NAME (default: risto_db)
"""

import argparse
import hashlib
import os
from datetime import datetime
from typing import Any, Dict

import mysql.connector


CREATE_PRODUCTS_SQL = """
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    birth_date DATE NOT NULL,
    avs_number VARCHAR(30) NOT NULL,
    personal_email VARCHAR(255) NOT NULL,
    address VARCHAR(255) NOT NULL,
    postal_code VARCHAR(20) NOT NULL,
    city VARCHAR(120) NOT NULL,
    canton VARCHAR(120) NOT NULL,
    role ENUM('manager', 'user') NOT NULL DEFAULT 'user',
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_avs (avs_number),
    UNIQUE KEY unique_email (personal_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create or update a manager account in risto_db")
    parser.add_argument("--email", required=True, help="Personal email for the admin account")
    parser.add_argument("--password", required=True, help="Plain text password for the admin account")
    parser.add_argument("--first-name", default="Admin", help="First name (default: Admin)")
    parser.add_argument("--last-name", default="User", help="Last name (default: User)")
    parser.add_argument("--birth-date", default="1980-01-01", help="Birth date in YYYY-MM-DD format")
    parser.add_argument("--avs-number", default="ADMIN-AVS-0001", help="Unique AVS/SSN identifier")
    parser.add_argument("--address", default="Via Risto 1", help="Street address")
    parser.add_argument("--postal-code", default="6900", help="Postal code")
    parser.add_argument("--city", default="Lugano", help="City")
    parser.add_argument("--canton", default="Ticino", help="Canton/Region")
    return parser.parse_args()


def validate_birth_date(value: str) -> str:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date().isoformat()
    except ValueError as exc:  # pragma: no cover - defensive guardrail
        raise SystemExit(f"Data di nascita non valida: {value}") from exc


def ensure_schema(cursor: Any) -> None:
    cursor.execute(CREATE_PRODUCTS_SQL)
    cursor.execute(CREATE_USERS_SQL)

    # Align existing installations that may predate the extended users schema
    cursor.execute("SHOW COLUMNS FROM users")
    column_rows = cursor.fetchall()
    existing_columns = {row[0] for row in column_rows}
    column_meta = {row[0]: {"null": row[2], "default": row[4]} for row in column_rows}

    required_columns = {
        "first_name": "VARCHAR(100) NOT NULL",
        "last_name": "VARCHAR(100) NOT NULL",
        "birth_date": "DATE NOT NULL",
        "avs_number": "VARCHAR(30) NOT NULL",
        "personal_email": "VARCHAR(255) NOT NULL",
        "address": "VARCHAR(255) NOT NULL",
        "postal_code": "VARCHAR(20) NOT NULL",
        "city": "VARCHAR(120) NOT NULL",
        "canton": "VARCHAR(120) NOT NULL",
        "role": "ENUM('manager', 'user') NOT NULL DEFAULT 'user'",
        "password_hash": "VARCHAR(255) NOT NULL",
    }

    for column, definition in required_columns.items():
        if column not in existing_columns:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")

    # Legacy installs used a single NOT NULL `name` column without default, which breaks
    # inserts that rely on the newer split name fields. Soften the column so inserts succeed.
    if "name" in column_meta:
        meta = column_meta["name"]
        if meta.get("null") == "NO" and meta.get("default") is None:
            cursor.execute("ALTER TABLE users MODIFY COLUMN name VARCHAR(255) NULL DEFAULT ''")

    # Ensure uniqueness constraints required by the app
    cursor.execute("SHOW INDEX FROM users")
    existing_indexes = {row[2] for row in cursor.fetchall()}
    if "unique_avs" not in existing_indexes:
        cursor.execute("ALTER TABLE users ADD UNIQUE KEY unique_avs (avs_number)")
    if "unique_email" not in existing_indexes:
        cursor.execute("ALTER TABLE users ADD UNIQUE KEY unique_email (personal_email)")


def get_db_config() -> Dict[str, Any]:
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", 3306)),
        "user": os.environ.get("DB_USER", "root"),
        "password": os.environ.get("DB_PASSWORD", "chcAdmin"),
        "database": os.environ.get("DB_NAME", "risto_db"),
        "charset": "utf8mb4",
    }


def create_or_update_admin(payload: Dict[str, str]) -> int:
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    try:
        with conn.cursor() as cursor:
            ensure_schema(cursor)
            cursor.execute(
                """
                INSERT INTO users (
                    first_name, last_name, birth_date, avs_number, personal_email,
                    address, postal_code, city, canton, role, password_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'manager', %s)
                ON DUPLICATE KEY UPDATE
                    first_name=VALUES(first_name),
                    last_name=VALUES(last_name),
                    birth_date=VALUES(birth_date),
                    avs_number=VALUES(avs_number),
                    address=VALUES(address),
                    postal_code=VALUES(postal_code),
                    city=VALUES(city),
                    canton=VALUES(canton),
                    role='manager',
                    password_hash=VALUES(password_hash)
                """,
                (
                    payload["first_name"],
                    payload["last_name"],
                    payload["birth_date"],
                    payload["avs_number"],
                    payload["personal_email"],
                    payload["address"],
                    payload["postal_code"],
                    payload["city"],
                    payload["canton"],
                    payload["password_hash"],
                ),
            )
            conn.commit()

            cursor.execute(
                "SELECT id FROM users WHERE personal_email=%s",
                (payload["personal_email"],),
            )
            row = cursor.fetchone()
            return int(row[0]) if row else 0
    finally:
        conn.close()


def main() -> None:
    args = parse_args()
    birth_date = validate_birth_date(args.birth_date)
    payload = {
        "first_name": args.first_name,
        "last_name": args.last_name,
        "birth_date": birth_date,
        "avs_number": args.avs_number,
        "personal_email": args.email,
        "address": args.address,
        "postal_code": args.postal_code,
        "city": args.city,
        "canton": args.canton,
        "role": "manager",
        "password_hash": hash_password(args.password),
    }
    admin_id = create_or_update_admin(payload)
    print(f"Admin creato/aggiornato con successo (ID: {admin_id}, email: {args.email})")


if __name__ == "__main__":
    main()