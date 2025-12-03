import os
import hashlib
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
import mysql.connector
from mysql.connector import pooling
from jinja2 import ChoiceLoader, FileSystemLoader, TemplateNotFound


def create_app() -> Flask:
    base_dir = os.path.abspath(os.path.dirname(__file__))
    template_dir = os.path.join(base_dir, "templates")
    static_dir = os.path.join(base_dir, "static")

    app = Flask(__name__, root_path=base_dir, template_folder=template_dir, static_folder=static_dir)
    app.secret_key = os.environ.get("SECRET_KEY", "ristodb-secret-key")

    upload_dir = os.path.join(base_dir, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    allowed_extensions = {"png", "jpg", "jpeg", "pdf", "doc", "docx", "heic"}

    # Harden template resolution across different working directories and deployments.
    fallback_template_dir = os.path.join(os.getcwd(), "templates")
    search_loaders = [
        FileSystemLoader(template_dir),
        FileSystemLoader(fallback_template_dir),
    ]

    # Preserve any existing loader (e.g., from Flask defaults) as a final option.
    if app.jinja_loader:
        search_loaders.append(app.jinja_loader)

    app.jinja_loader = ChoiceLoader(search_loaders)

    db_config = {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", 3306)),
        "user": os.environ.get("DB_USER", "root"),
        "password": os.environ.get("DB_PASSWORD", "chcAdmin"),
        "database": os.environ.get("DB_NAME", "risto_db"),
        "charset": "utf8mb4",
    }

    pool: Optional[pooling.MySQLConnectionPool] = None

    def get_pool() -> pooling.MySQLConnectionPool:
        nonlocal pool
        if pool is None:
            pool = pooling.MySQLConnectionPool(pool_name="ristodb_pool", pool_size=5, **db_config)
        return pool

    def get_connection():
        return get_pool().get_connection()

    def init_db() -> None:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS products (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        price DECIMAL(10,2) NOT NULL,
                        stock INT NOT NULL DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """
                )

                cursor.execute(
                    """
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
                )

                cursor.execute("SHOW COLUMNS FROM users")
                columns = cursor.fetchall()
                existing_columns = {row[0] for row in columns}
                column_meta = {row[0]: {"null": row[2], "default": row[4]} for row in columns}

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

                if "name" in column_meta:
                    meta = column_meta["name"]
                    if meta.get("null") == "NO" and meta.get("default") is None:
                        cursor.execute("ALTER TABLE users MODIFY COLUMN name VARCHAR(255) NULL DEFAULT ''")

                cursor.execute("SHOW INDEX FROM users")
                existing_indexes = {row[2] for row in cursor.fetchall()}
                if "unique_avs" not in existing_indexes:
                    cursor.execute("ALTER TABLE users ADD UNIQUE KEY unique_avs (avs_number)")
                if "unique_email" not in existing_indexes:
                    cursor.execute("ALTER TABLE users ADD UNIQUE KEY unique_email (personal_email)")

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS clients (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        phone VARCHAR(50) DEFAULT NULL,
                        email VARCHAR(255) DEFAULT NULL,
                        address VARCHAR(255) DEFAULT NULL,
                        city VARCHAR(120) DEFAULT NULL,
                        notes TEXT DEFAULT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS client_machines (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        client_id INT NOT NULL,
                        brand VARCHAR(120) DEFAULT NULL,
                        model VARCHAR(120) DEFAULT NULL,
                        notes TEXT DEFAULT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        CONSTRAINT fk_machines_client FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS machine_files (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        machine_id INT NOT NULL,
                        file_path VARCHAR(255) NOT NULL,
                        original_name VARCHAR(255) DEFAULT NULL,
                        kind ENUM('photo', 'document') NOT NULL DEFAULT 'document',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT fk_files_machine FOREIGN KEY (machine_id) REFERENCES client_machines(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """
                )

                conn.commit()

    def render_page(template_name: str, **context):
        context["session_user"] = session.get("user")
        try:
            return render_template(template_name, **context)
        except TemplateNotFound:
            app.logger.error("Template non trovato: %s", template_name)
            # Fallback minimale per evitare 500 su deploy con template mancanti
            return (
                f"<h1>Template mancante</h1><p>Il file <strong>{template_name}</strong> "
                "non è stato trovato sul server.</p>",
                500,
                {"Content-Type": "text/html"},
            )

    def require_login_api():
        if not session.get("user"):
            return jsonify({"error": "Autenticazione richiesta"}), 401
        return None

    def require_manager_api():
        user = session.get("user")
        if not user:
            return jsonify({"error": "Autenticazione richiesta"}), 401
        if user.get("role") != "manager":
            return jsonify({"error": "Permesso negato"}), 403
        return None

    def ensure_manager_page():
        user = session.get("user")
        if not user:
            return redirect(url_for("login_page"))
        if user.get("role") != "manager":
            return redirect(url_for("clients_manage_page"))
        return None

    def ensure_logged_page():
        if not session.get("user"):
            return redirect(url_for("login_page"))
        return None

    def save_files(file_storage_list, machine_id: int) -> List[Dict[str, Any]]:
        saved: List[Dict[str, Any]] = []
        for file_storage in file_storage_list:
            if not file_storage.filename:
                continue
            ext = file_storage.filename.rsplit(".", 1)[-1].lower()
            if ext not in allowed_extensions:
                continue
            filename = f"{uuid.uuid4().hex}.{ext}"
            filepath = os.path.join(upload_dir, filename)
            file_storage.save(filepath)
            kind = "photo" if file_storage.mimetype.startswith("image/") else "document"
            saved.append(
                {
                    "machine_id": machine_id,
                    "file_path": filename,
                    "original_name": file_storage.filename,
                    "kind": kind,
                }
            )
        return saved

    @app.route("/health", methods=["GET"])
    def health():
        return {"status": "ok"}

    def redirect_after_login() -> str:
        user = session.get("user") or {}
        role = str(user.get("role", "")).lower()
        return "/users/manage" if role == "manager" else "/clients/manage"

    @app.route("/", methods=["GET"])
    @app.route("/home", methods=["GET"])
    @app.route("/dashboard", methods=["GET"])
    def home():
        if session.get("user"):
            return redirect(redirect_after_login())
        return redirect(url_for("login_page"))

    @app.route("/login", methods=["GET"])
    def login_page():
        if session.get("user"):
            return redirect(redirect_after_login())
        return render_page(
            "login.html",
            title="Login · Risto Solution",
            hero_title="Benvenuto in Risto Solution",
            hero_text="Accedi per gestire utenti, prodotti e processi operativi",
        )

    @app.route("/auth/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"status": "ok"})

    @app.route("/forgot-password", methods=["GET"])
    def forgot_password_page():
        return render_page(
            "forgot_password.html",
            title="Recupera password · Risto Solution",
            hero_title="Recupera l'accesso",
            hero_text="Imposta una nuova password usando l'e-mail personale",
        )

    @app.route("/users/manage", methods=["GET"])
    def users_manage_page():
        gate = ensure_manager_page()
        if gate:
            return gate
        return render_page(
            "users_manage.html",
            title="Gestione utenti · Risto Solution",
            hero_title="Gestione utenti",
            hero_text="Crea, aggiorna o resetta gli account del gestionale",
            active_nav="users",
        )

    @app.route("/activities/manage", methods=["GET"])
    def activities_manage_page():
        gate = ensure_manager_page()
        if gate:
            return gate
        return render_page(
            "activities_manage.html",
            title="Gestione attività · Risto Solution",
            hero_title="Gestione attività",
            hero_text="Pianifica e monitora le attività operative",
            active_nav="activities",
        )

    @app.route("/clients/manage", methods=["GET"])
    def clients_manage_page():
        gate = ensure_logged_page()
        if gate:
            return gate
        return render_page(
            "clients_manage.html",
            title="Clienti · Risto Solution",
            hero_title="Clienti",
            hero_text="Schede clienti e macchinari aggiornabili anche da smartphone",
            active_nav="clients",
        )

    @app.route("/uploads/<path:filename>")
    def uploaded_file(filename: str):
        return send_from_directory(upload_dir, filename)

    def fetch_products() -> List[Dict[str, Any]]:
        with get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT id, name, price, stock, created_at, updated_at FROM products")
                return cursor.fetchall()

    def fetch_product(product_id: int) -> Optional[Dict[str, Any]]:
        with get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(
                    "SELECT id, name, price, stock, created_at, updated_at FROM products WHERE id=%s",
                    (product_id,),
                )
                return cursor.fetchone()

    def insert_product(name: str, price: float, stock: int) -> int:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO products (name, price, stock) VALUES (%s, %s, %s)",
                    (name, price, stock),
                )
                conn.commit()
                return cursor.lastrowid

    def update_product(product_id: int, name: str, price: float, stock: int) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE products SET name=%s, price=%s, stock=%s WHERE id=%s",
                    (name, price, stock, product_id),
                )
                conn.commit()
                return cursor.rowcount > 0

    def delete_product(product_id: int) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
                conn.commit()
                return cursor.rowcount > 0

    def serialize_user(row: Dict[str, Any]) -> Dict[str, Any]:
        row = dict(row)
        row.pop("password_hash", None)
        return row

    def fetch_users() -> List[Dict[str, Any]]:
        with get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(
                    """
                    SELECT id, first_name, last_name, birth_date, avs_number, personal_email,
                           address, postal_code, city, canton, role, created_at, updated_at, password_hash
                    FROM users
                    ORDER BY id DESC
                    """
                )
                return [serialize_user(row) for row in cursor.fetchall()]

    def fetch_user(user_id: int) -> Optional[Dict[str, Any]]:
        with get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(
                    """
                    SELECT id, first_name, last_name, birth_date, avs_number, personal_email,
                           address, postal_code, city, canton, role, created_at, updated_at, password_hash
                    FROM users WHERE id=%s
                    """,
                    (user_id,),
                )
                row = cursor.fetchone()
                return serialize_user(row) if row else None

    def fetch_user_by_email(email: str) -> Optional[Dict[str, Any]]:
        with get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(
                    """
                    SELECT id, first_name, last_name, birth_date, avs_number, personal_email,
                           address, postal_code, city, canton, role, created_at, updated_at, password_hash
                    FROM users WHERE personal_email=%s
                    """,
                    (email,),
                )
                row = cursor.fetchone()
                return serialize_user(row) if row else None

    def insert_user(payload: Dict[str, Any]) -> int:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (
                        first_name, last_name, birth_date, avs_number, personal_email, address,
                        postal_code, city, canton, role, password_hash
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                        payload["role"],
                        payload["password_hash"],
                    ),
                )
                conn.commit()
                return cursor.lastrowid

    def update_user(user_id: int, payload: Dict[str, Any]) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users SET
                        first_name=%s, last_name=%s, birth_date=%s, avs_number=%s, personal_email=%s,
                        address=%s, postal_code=%s, city=%s, canton=%s, role=%s
                    WHERE id=%s
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
                        payload["role"],
                        user_id,
                    ),
                )
                conn.commit()
                return cursor.rowcount > 0

    def delete_user(user_id: int) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
                conn.commit()
                return cursor.rowcount > 0

    def update_user_password(user_id: int, password_hash: str) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET password_hash=%s WHERE id=%s",
                    (password_hash, user_id),
                )
                conn.commit()
                return cursor.rowcount > 0

    def update_user_password_by_email(email: str, password_hash: str) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET password_hash=%s WHERE personal_email=%s",
                    (password_hash, email),
                )
                conn.commit()
                return cursor.rowcount > 0

    def fetch_clients() -> List[Dict[str, Any]]:
        with get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(
                    """
                    SELECT id, name, phone, email, address, city, notes, created_at, updated_at,
                           (SELECT COUNT(*) FROM client_machines cm WHERE cm.client_id = clients.id) as machines_count
                    FROM clients
                    ORDER BY updated_at DESC
                    """
                )
                return cursor.fetchall()

    def fetch_client_detail(client_id: int) -> Optional[Dict[str, Any]]:
        with get_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(
                    "SELECT id, name, phone, email, address, city, notes, created_at, updated_at FROM clients WHERE id=%s",
                    (client_id,),
                )
                client = cursor.fetchone()
                if not client:
                    return None
                cursor.execute(
                    """
                    SELECT id, brand, model, notes, created_at, updated_at
                    FROM client_machines
                    WHERE client_id=%s
                    ORDER BY updated_at DESC
                    """,
                    (client_id,),
                )
                machines = cursor.fetchall()
                for machine in machines:
                    cursor.execute(
                        "SELECT id, file_path, original_name, kind, created_at FROM machine_files WHERE machine_id=%s",
                        (machine["id"],),
                    )
                    machine["files"] = cursor.fetchall()
                client["machines"] = machines
                return client

    def insert_client(payload: Dict[str, Any]) -> int:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO clients (name, phone, email, address, city, notes)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        payload.get("name"),
                        payload.get("phone"),
                        payload.get("email"),
                        payload.get("address"),
                        payload.get("city"),
                        payload.get("notes"),
                    ),
                )
                conn.commit()
                return cursor.lastrowid

    def update_client(client_id: int, payload: Dict[str, Any]) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE clients SET name=%s, phone=%s, email=%s, address=%s, city=%s, notes=%s
                    WHERE id=%s
                    """,
                    (
                        payload.get("name"),
                        payload.get("phone"),
                        payload.get("email"),
                        payload.get("address"),
                        payload.get("city"),
                        payload.get("notes"),
                        client_id,
                    ),
                )
                conn.commit()
                return cursor.rowcount > 0

    def delete_client(client_id: int) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM clients WHERE id=%s", (client_id,))
                conn.commit()
                return cursor.rowcount > 0

    def insert_machine(client_id: int, payload: Dict[str, Any]) -> int:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO client_machines (client_id, brand, model, notes)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        client_id,
                        payload.get("brand"),
                        payload.get("model"),
                        payload.get("notes"),
                    ),
                )
                conn.commit()
                return cursor.lastrowid

    def update_machine(machine_id: int, payload: Dict[str, Any]) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE client_machines
                    SET brand=%s, model=%s, notes=%s, updated_at=CURRENT_TIMESTAMP
                    WHERE id=%s
                    """,
                    (
                        payload.get("brand"),
                        payload.get("model"),
                        payload.get("notes"),
                        machine_id,
                    ),
                )
                conn.commit()
                return cursor.rowcount > 0

    def delete_machine(machine_id: int) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM client_machines WHERE id=%s", (machine_id,))
                conn.commit()
                return cursor.rowcount > 0

    def store_files(file_rows: List[Dict[str, Any]]):
        if not file_rows:
            return
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.executemany(
                    "INSERT INTO machine_files (machine_id, file_path, original_name, kind) VALUES (%s, %s, %s, %s)",
                    [
                        (row["machine_id"], row["file_path"], row.get("original_name"), row.get("kind", "document"))
                        for row in file_rows
                    ],
                )
                conn.commit()

    @app.route("/products", methods=["GET"])
    def list_products():
        products = fetch_products()
        return jsonify(products)

    @app.route("/products", methods=["POST"])
    def create_product():
        payload = request.get_json() or {}
        name = payload.get("name")
        price = payload.get("price")
        stock = payload.get("stock", 0)

        if not name or price is None:
            return jsonify({"error": "name and price are required"}), 400

        try:
            product_id = insert_product(str(name), float(price), int(stock))
            product = fetch_product(product_id)
            return jsonify(product), 201
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/products/<int:product_id>", methods=["GET"])
    def get_product(product_id: int):
        product = fetch_product(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        return jsonify(product)

    @app.route("/products/<int:product_id>", methods=["PUT"])
    def update_product_route(product_id: int):
        payload = request.get_json() or {}
        name = payload.get("name")
        price = payload.get("price")
        stock = payload.get("stock")

        if name is None or price is None or stock is None:
            return jsonify({"error": "name, price and stock are required"}), 400

        try:
            updated = update_product(product_id, str(name), float(price), int(stock))
            if not updated:
                return jsonify({"error": "Product not found"}), 404
            product = fetch_product(product_id)
            return jsonify(product)
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/products/<int:product_id>", methods=["DELETE"])
    def delete_product_route(product_id: int):
        try:
            deleted = delete_product(product_id)
            if not deleted:
                return jsonify({"error": "Product not found"}), 404
            return "", 204
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    def normalize_birth_date(raw_date: str) -> Optional[str]:
        """Return YYYY-MM-DD formatted date if parsable from either YYYY-MM-DD or DD.MM.YYYY."""
        try:
            if "." in raw_date:
                return datetime.strptime(raw_date, "%d.%m.%Y").strftime("%Y-%m-%d")
            return datetime.strptime(raw_date, "%Y-%m-%d").strftime("%Y-%m-%d")
        except (TypeError, ValueError):
            return None

    def validate_user_payload(payload: Dict[str, Any], require_password: bool = True) -> Optional[str]:
        required_fields = [
            "first_name",
            "last_name",
            "birth_date",
            "avs_number",
            "personal_email",
            "address",
            "postal_code",
            "city",
            "canton",
            "role",
        ]
        if require_password:
            required_fields.append("password")

        missing = [field for field in required_fields if not payload.get(field)]
        if missing:
            return f"Missing fields: {', '.join(missing)}"

        if payload.get("role") not in {"manager", "user"}:
            return "role must be 'manager' or 'user'"

        normalized_birth_date = normalize_birth_date(payload["birth_date"])
        if not normalized_birth_date:
            return "birth_date must be in format YYYY-MM-DD or DD.MM.YYYY"
        payload["birth_date"] = normalized_birth_date

        return None

    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def verify_password(password: str, password_hash: str) -> bool:
        return hash_password(password) == password_hash

    @app.route("/users", methods=["GET"])
    def list_users():
        guard = require_manager_api()
        if guard:
            return guard
        users = fetch_users()
        return jsonify(users)

    @app.route("/users", methods=["POST"])
    def create_user():
        guard = require_manager_api()
        if guard:
            return guard
        payload = request.get_json() or {}
        error = validate_user_payload(payload, require_password=True)
        if error:
            return jsonify({"error": error}), 400

        user_data = {**payload, "password_hash": hash_password(payload["password"])}
        try:
            user_id = insert_user(user_data)
            user = fetch_user(user_id)
            return jsonify(user), 201
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/users/<int:user_id>", methods=["GET"])
    def get_user(user_id: int):
        guard = require_manager_api()
        if guard:
            return guard
        user = fetch_user(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify(user)

    @app.route("/users/<int:user_id>", methods=["PUT"])
    def update_user_route(user_id: int):
        guard = require_manager_api()
        if guard:
            return guard
        payload = request.get_json() or {}
        error = validate_user_payload(payload, require_password=False)
        if error:
            return jsonify({"error": error}), 400

        try:
            updated = update_user(user_id, payload)
            if not updated:
                return jsonify({"error": "User not found"}), 404
            user = fetch_user(user_id)
            return jsonify(user)
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/users/<int:user_id>", methods=["DELETE"])
    def delete_user_route(user_id: int):
        guard = require_manager_api()
        if guard:
            return guard
        try:
            deleted = delete_user(user_id)
            if not deleted:
                return jsonify({"error": "User not found"}), 404
            return "", 204
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/users/<int:user_id>/reset_password", methods=["POST"])
    def reset_password_route(user_id: int):
        guard = require_manager_api()
        if guard:
            return guard
        payload = request.get_json() or {}
        new_password = payload.get("password")
        if not new_password:
            return jsonify({"error": "password is required"}), 400

        try:
            updated = update_user_password(user_id, hash_password(new_password))
            if not updated:
                return jsonify({"error": "User not found"}), 404
            user = fetch_user(user_id)
            return jsonify(user)
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/clients", methods=["GET"])
    def list_clients_route():
        guard = require_login_api()
        if guard:
            return guard
        clients = fetch_clients()
        return jsonify(clients)

    @app.route("/clients", methods=["POST"])
    def create_client_route():
        guard = require_login_api()
        if guard:
            return guard
        payload = request.get_json() or {}
        if not payload.get("name"):
            return jsonify({"error": "name is required"}), 400
        try:
            client_id = insert_client(payload)
            client = fetch_client_detail(client_id)
            return jsonify(client), 201
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/clients/<int:client_id>", methods=["GET"])
    def get_client_route(client_id: int):
        guard = require_login_api()
        if guard:
            return guard
        client = fetch_client_detail(client_id)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        return jsonify(client)

    @app.route("/clients/<int:client_id>", methods=["PUT"])
    def update_client_route(client_id: int):
        guard = require_login_api()
        if guard:
            return guard
        payload = request.get_json() or {}
        if not payload.get("name"):
            return jsonify({"error": "name is required"}), 400
        try:
            updated = update_client(client_id, payload)
            if not updated:
                return jsonify({"error": "Client not found"}), 404
            client = fetch_client_detail(client_id)
            return jsonify(client)
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/clients/<int:client_id>", methods=["DELETE"])
    def delete_client_route(client_id: int):
        guard = require_login_api()
        if guard:
            return guard
        try:
            deleted = delete_client(client_id)
            if not deleted:
                return jsonify({"error": "Client not found"}), 404
            return "", 204
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/clients/<int:client_id>/machines", methods=["GET"])
    def list_machines_route(client_id: int):
        guard = require_login_api()
        if guard:
            return guard
        client = fetch_client_detail(client_id)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        return jsonify(client.get("machines", []))

    @app.route("/clients/<int:client_id>/machines", methods=["POST"])
    def create_machine_route(client_id: int):
        guard = require_login_api()
        if guard:
            return guard
        # Accept multipart for smartphone uploads
        payload = request.form or {}
        if not fetch_client_detail(client_id):
            return jsonify({"error": "Client not found"}), 404
        if not payload.get("brand") and not payload.get("model"):
            return jsonify({"error": "brand or model is required"}), 400
        try:
            machine_id = insert_machine(client_id, payload)
            files_saved = save_files(request.files.getlist("files"), machine_id)
            store_files(files_saved)
            machine = None
            client = fetch_client_detail(client_id)
            if client:
                for m in client.get("machines", []):
                    if m.get("id") == machine_id:
                        machine = m
                        break
            return jsonify(machine or {}), 201
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/clients/<int:client_id>/machines/<int:machine_id>", methods=["PUT"])
    def update_machine_route(client_id: int, machine_id: int):
        guard = require_login_api()
        if guard:
            return guard
        payload = request.get_json() or request.form or {}
        client = fetch_client_detail(client_id)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        if machine_id not in [m.get("id") for m in client.get("machines", [])]:
            return jsonify({"error": "Machine not found"}), 404
        brand = payload.get("brand")
        model = payload.get("model")
        if not brand or not model:
            return jsonify({"error": "brand and model are required"}), 400
        try:
            updated = update_machine(machine_id, payload)
            if not updated:
                return jsonify({"error": "Machine not found"}), 404
            updated_client = fetch_client_detail(client_id)
            machine = None
            if updated_client:
                for m in updated_client.get("machines", []):
                    if m.get("id") == machine_id:
                        machine = m
                        break
            return jsonify(machine or {}), 200
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/clients/<int:client_id>/machines/<int:machine_id>", methods=["DELETE"])
    def delete_machine_route(client_id: int, machine_id: int):
        guard = require_login_api()
        if guard:
            return guard
        client = fetch_client_detail(client_id)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        if machine_id not in [m.get("id") for m in client.get("machines", [])]:
            return jsonify({"error": "Machine not found"}), 404
        try:
            deleted = delete_machine(machine_id)
            if not deleted:
                return jsonify({"error": "Machine not found"}), 404
            return "", 204
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/clients/<int:client_id>/machines/<int:machine_id>/files", methods=["POST"])
    def upload_machine_files_route(client_id: int, machine_id: int):
        guard = require_login_api()
        if guard:
            return guard
        client = fetch_client_detail(client_id)
        if not client:
            return jsonify({"error": "Client not found"}), 404
        if machine_id not in [m.get("id") for m in client.get("machines", [])]:
            return jsonify({"error": "Machine not found"}), 404
        files_saved = save_files(request.files.getlist("files"), machine_id)
        store_files(files_saved)
        return jsonify(files_saved), 201

    @app.route("/auth/login", methods=["POST"])
    def auth_login():
        payload = request.get_json() or {}
        email = payload.get("personal_email")
        password = payload.get("password")
        if not email or not password:
            return jsonify({"error": "personal_email and password are required"}), 400

        try:
            with get_connection() as conn:
                with conn.cursor(dictionary=True) as cursor:
                    cursor.execute(
                        """
                        SELECT id, first_name, last_name, birth_date, avs_number, personal_email,
                               address, postal_code, city, canton, role, created_at, updated_at, password_hash
                        FROM users WHERE personal_email=%s
                        """,
                        (email,),
                    )
                    row = cursor.fetchone()
        except mysql.connector.Error as exc:
            app.logger.error("Login failed due to database error: %s", exc)
            return jsonify({"error": "Errore di connessione al database"}), 500

        if not row or not verify_password(password, row.get("password_hash", "")):
            return jsonify({"error": "Credenziali non valide"}), 401

        role = str(row.get("role", "")).lower()
        session["user"] = {
            "id": row.get("id"),
            "role": role,
            "name": f"{row.get('first_name', '')} {row.get('last_name', '')}".strip(),
        }
        return jsonify({"user": serialize_user(row), "redirect": redirect_after_login()})

    @app.route("/auth/forgot-password", methods=["POST"])
    def forgot_password():
        payload = request.get_json() or {}
        email = payload.get("personal_email")
        new_password = payload.get("password")
        if not email or not new_password:
            return jsonify({"error": "personal_email and password are required"}), 400

        try:
            updated = update_user_password_by_email(email, hash_password(new_password))
            if not updated:
                return jsonify({"error": "Utente non trovato"}), 404
            user = fetch_user_by_email(email)
            return jsonify(user)
        except mysql.connector.Error as exc:
            return jsonify({"error": str(exc)}), 500

    try:
        init_db()
    except mysql.connector.Error as exc:
        app.logger.error("Database initialization failed: %s", exc)
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5007)