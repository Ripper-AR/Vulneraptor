"""
vulnerable_app.py
=================

INTENTIONALLY VULNERABLE LOCAL WEB SECURITY LAB

Purpose:
    This application is designed as a realistic target for testing
    vulnerability scanners such as:

        - SQL Injection scanner
        - XSS scanner
        - Security configuration scanner
        - Recon/scanning tools

WARNING:
    This application is intentionally vulnerable.

    It binds ONLY to 127.0.0.1.
    Do NOT expose it to your LAN, Internet, VPN, public interface,
    Docker bridge, or production environment.

Run:
    python vulnerable_app.py

Open:
    http://127.0.0.1:5000/

Useful scanner targets:
    http://127.0.0.1:5000/
    http://127.0.0.1:5000/search?q=admin
    http://127.0.0.1:5000/user?username=admin
    http://127.0.0.1:5000/product?id=1
    http://127.0.0.1:5000/profile?id=1
    http://127.0.0.1:5000/api/users?name=admin
    http://127.0.0.1:5000/api/products?search=laptop

Intentionally vulnerable areas include:

    SQL Injection:
        /user
        /search
        /product
        /login
        /profile
        /api/users
        /api/products
        /admin/users

    Reflected XSS:
        /search
        /user
        /profile

    Stored XSS:
        /comments
        /comments/add
        /feedback

    Other security issues:
        - Missing security headers
        - Verbose database errors
        - Information disclosure
        - Weak authentication logic
        - Open redirect
        - Insecure cookies
        - Debug information
        - Predictable IDs
"""

import sqlite3
import html
import json
import os
import secrets
import traceback

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote


# ============================================================
# CONFIGURATION
# ============================================================

HOST = "127.0.0.1"
PORT = 5000

DB_FILE = "vulnerable_lab.db"


# ============================================================
# DATABASE
# ============================================================

conn = sqlite3.connect(
    DB_FILE,
    check_same_thread=False
)

conn.row_factory = sqlite3.Row

cursor = conn.cursor()


def init_database():
    """
    Create a reasonably large database for the vulnerable lab.
    """

    cursor.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS comments;
        DROP TABLE IF EXISTS feedback;
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS logs;


        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            secret TEXT NOT NULL
        );


        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT NOT NULL,
            stock INTEGER NOT NULL
        );


        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );


        CREATE TABLE feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );


        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total REAL
        );


        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT,
            ip TEXT,
            user_agent TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    users = [
        (
            "admin",
            "admin123",
            "admin@vulnerable.local",
            "administrator",
            "FLAG{SQL_INJECTION_ADMIN_SECRET}"
        ),
        (
            "alice",
            "alice123",
            "alice@vulnerable.local",
            "user",
            "AlicePrivateSecret"
        ),
        (
            "bob",
            "bob123",
            "bob@vulnerable.local",
            "user",
            "BobPrivateSecret"
        ),
        (
            "developer",
            "dev123",
            "developer@vulnerable.local",
            "developer",
            "FLAG{DEVELOPER_DATABASE_SECRET}"
        ),
        (
            "security",
            "security123",
            "security@vulnerable.local",
            "security",
            "FLAG{SECURITY_TEAM_SECRET}"
        ),
    ]


    cursor.executemany(
        """
        INSERT INTO users
        (username, password, email, role, secret)
        VALUES (?, ?, ?, ?, ?)
        """,
        users
    )


    # --------------------------------------------------------
    # PRODUCTS
    # --------------------------------------------------------

    products = [
        (
            "Laptop Pro 15",
            "electronics",
            1299.99,
            "Professional laptop with 32GB RAM.",
            14
        ),
        (
            "Wireless Keyboard",
            "electronics",
            79.99,
            "Mechanical wireless keyboard.",
            43
        ),
        (
            "Gaming Mouse",
            "electronics",
            59.99,
            "High precision gaming mouse.",
            72
        ),
        (
            "USB Security Key",
            "security",
            49.99,
            "Hardware authentication key.",
            31
        ),
        (
            "Network Scanner",
            "security",
            199.99,
            "Network monitoring appliance.",
            8
        ),
        (
            "Python Security Book",
            "books",
            39.99,
            "Security programming reference.",
            25
        ),
        (
            "Linux Administration",
            "books",
            44.99,
            "Linux administration handbook.",
            18
        ),
        (
            "Raspberry Pi 5",
            "hardware",
            99.99,
            "Small single-board computer.",
            55
        ),
        (
            "WiFi Adapter",
            "network",
            34.99,
            "USB wireless network adapter.",
            90
        ),
        (
            "Ethernet Cable",
            "network",
            9.99,
            "Cat6 Ethernet cable.",
            200
        ),
    ]


    cursor.executemany(
        """
        INSERT INTO products
        (name, category, price, description, stock)
        VALUES (?, ?, ?, ?, ?)
        """,
        products
    )


    # --------------------------------------------------------
    # COMMENTS
    # --------------------------------------------------------

    comments = [
        (
            "alice",
            "This website is useful."
        ),
        (
            "bob",
            "I like the security lab."
        ),
        (
            "developer",
            "Testing application."
        ),
    ]


    cursor.executemany(
        """
        INSERT INTO comments
        (username, comment)
        VALUES (?, ?)
        """,
        comments
    )


    # --------------------------------------------------------
    # ORDERS
    # --------------------------------------------------------

    orders = [
        (2, 1, 1, 1299.99),
        (3, 2, 2, 159.98),
        (2, 4, 1, 49.99),
        (4, 5, 1, 199.99),
    ]


    cursor.executemany(
        """
        INSERT INTO orders
        (user_id, product_id, quantity, total)
        VALUES (?, ?, ?, ?)
        """,
        orders
    )


    conn.commit()


# ============================================================
# HTML HELPERS
# ============================================================

def page(title, content):
    """
    Main HTML template.

    Intentionally missing several security headers.
    """

    return f"""
<!DOCTYPE html>
<html>
<head>

    <meta charset="UTF-8">

    <title>{title}</title>

    <style>

        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f4f6f8;
            color: #222;
        }}

        header {{
            background: #17202a;
            color: white;
            padding: 20px;
        }}

        nav a {{
            color: white;
            margin-right: 20px;
            text-decoration: none;
        }}

        .container {{
            max-width: 1100px;
            margin: 30px auto;
            padding: 20px;
        }}

        .card {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px #ccc;
        }}

        input, textarea, select {{
            width: 100%;
            padding: 10px;
            margin: 8px 0 15px;
            box-sizing: border-box;
        }}

        button {{
            background: #2874a6;
            color: white;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }}

        th {{
            background: #eee;
        }}

        .warning {{
            background: #fff3cd;
            padding: 15px;
            border-left: 5px solid #ffc107;
        }}

        .danger {{
            background: #f8d7da;
            padding: 15px;
            border-left: 5px solid #dc3545;
        }}

        code {{
            background: #eee;
            padding: 2px 5px;
        }}

    </style>

</head>

<body>

<header>

    <h1>Vulnerable Security Lab</h1>

    <nav>
        <a href="/">Home</a>
        <a href="/search">Search</a>
        <a href="/products">Products</a>
        <a href="/comments">Comments</a>
        <a href="/feedback">Feedback</a>
        <a href="/login">Login</a>
        <a href="/debug">Debug</a>
    </nav>

</header>

<div class="container">

{content}

</div>

</body>
</html>
"""


def json_response(handler, data, status=200):

    body = json.dumps(
        data,
        indent=4
    )

    handler.send_response(status)

    handler.send_header(
        "Content-Type",
        "application/json"
    )

    handler.end_headers()

    handler.wfile.write(
        body.encode()
    )


def text_response(handler, body, status=200):

    handler.send_response(status)

    handler.send_header(
        "Content-Type",
        "text/plain; charset=utf-8"
    )

    handler.end_headers()

    handler.wfile.write(
        body.encode()
    )


def html_response(handler, body, status=200):

    handler.send_response(status)

    handler.send_header(
        "Content-Type",
        "text/html; charset=utf-8"
    )

    # Intentionally insecure cookie.
    handler.send_header(
        "Set-Cookie",
        "session=" + secrets.token_hex(8)
    )

    # Intentionally missing:
    # X-Frame-Options
    # Content-Security-Policy
    # X-Content-Type-Options
    # Strict-Transport-Security
    # Referrer-Policy

    handler.end_headers()

    handler.wfile.write(
        body.encode()
    )


# ============================================================
# REQUEST HANDLER
# ============================================================

class Handler(BaseHTTPRequestHandler):

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    def do_GET(self):

        parsed = urlparse(self.path)

        path = parsed.path

        params = parse_qs(
            parsed.query,
            keep_blank_values=True
        )


        self.log_request(path)


        try:

            # ------------------------------------------------
            # HOME
            # ------------------------------------------------

            if path == "/":

                self.home()

            # ------------------------------------------------
            # SEARCH
            # ------------------------------------------------

            elif path == "/search":

                self.search(params)

            # ------------------------------------------------
            # USER
            # ------------------------------------------------

            elif path == "/user":

                self.user(params)

            # ------------------------------------------------
            # PRODUCT
            # ------------------------------------------------

            elif path == "/product":

                self.product(params)

            # ------------------------------------------------
            # PRODUCTS
            # ------------------------------------------------

            elif path == "/products":

                self.products(params)

            # ------------------------------------------------
            # PROFILE
            # ------------------------------------------------

            elif path == "/profile":

                self.profile(params)

            # ------------------------------------------------
            # LOGIN
            # ------------------------------------------------

            elif path == "/login":

                self.login_page()

            # ------------------------------------------------
            # API USERS
            # ------------------------------------------------

            elif path == "/api/users":

                self.api_users(params)

            # ------------------------------------------------
            # API PRODUCTS
            # ------------------------------------------------

            elif path == "/api/products":

                self.api_products(params)

            # ------------------------------------------------
            # ADMIN USERS
            # ------------------------------------------------

            elif path == "/admin/users":

                self.admin_users(params)

            # ------------------------------------------------
            # COMMENTS
            # ------------------------------------------------

            elif path == "/comments":

                self.comments()

            # ------------------------------------------------
            # FEEDBACK
            # ------------------------------------------------

            elif path == "/feedback":

                self.feedback()

            # ------------------------------------------------
            # REDIRECT
            # ------------------------------------------------

            elif path == "/redirect":

                self.redirect(params)

            # ------------------------------------------------
            # DEBUG
            # ------------------------------------------------

            elif path == "/debug":

                self.debug()

            # ------------------------------------------------
            # HEADERS
            # ------------------------------------------------

            elif path == "/headers":

                self.headers()

            else:

                self.not_found()

        except Exception as exc:

            self.server_error(exc)


    # ========================================================
    # POST
    # ========================================================

    def do_POST(self):

        parsed = urlparse(self.path)

        path = parsed.path

        length = int(
            self.headers.get(
                "Content-Length",
                0
            )
        )

        raw_body = self.rfile.read(
            length
        ).decode(
            errors="replace"
        )

        params = parse_qs(
            raw_body,
            keep_blank_values=True
        )


        try:

            if path == "/login":

                self.login(params)

            elif path == "/comments/add":

                self.add_comment(params)

            elif path == "/feedback":

                self.add_feedback(params)

            else:

                self.not_found()

        except Exception as exc:

            self.server_error(exc)


    # ========================================================
    # HOME
    # ========================================================

    def home(self):

        content = """

<div class="card">

    <h2>Local Vulnerable Web Application</h2>

    <div class="warning">

        This application is intentionally vulnerable.
        It is designed for security-scanner development.

    </div>

</div>


<div class="card">

    <h2>Testing Targets</h2>

    <ul>

        <li>
            <code>/search?q=test</code>
        </li>

        <li>
            <code>/user?username=admin</code>
        </li>

        <li>
            <code>/product?id=1</code>
        </li>

        <li>
            <code>/profile?id=1</code>
        </li>

        <li>
            <code>/api/users?name=admin</code>
        </li>

        <li>
            <code>/api/products?search=laptop</code>
        </li>

        <li>
            <code>/admin/users?sort=username</code>
        </li>

        <li>
            <code>/comments</code>
        </li>

        <li>
            <code>/feedback</code>
        </li>

    </ul>

</div>


<div class="card">

    <h2>Database</h2>

    <p>
        SQLite database with users, products, orders,
        comments and feedback.
    </p>

</div>

"""

        html_response(
            self,
            page(
                "Vulnerable Lab",
                content
            )
        )


    # ========================================================
    # SEARCH
    # ========================================================

    def search(self, params):

        q = params.get(
            "q",
            [""]
        )[0]


        # ====================================================
        # INTENTIONALLY VULNERABLE SQL
        # ====================================================

        query = f"""
            SELECT id, name, category, price, description
            FROM products
            WHERE name LIKE '%{q}%'
               OR category LIKE '%{q}%'
        """


        try:

            cursor.execute(
                query
            )

            rows = cursor.fetchall()

        except sqlite3.Error as exc:

            body = f"""
            SEARCH DATABASE ERROR

            Error:
                {exc}

            Query:
                {query}
            """

            text_response(
                self,
                body,
                500
            )

            return


        results = ""

        for row in rows:

            # q is intentionally reflected without escaping.
            results += f"""
            <tr>

                <td>
                    {row["id"]}
                </td>

                <td>
                    {row["name"]}
                </td>

                <td>
                    {row["category"]}
                </td>

                <td>
                    ${row["price"]}
                </td>

            </tr>
            """


        # INTENTIONALLY REFLECTED XSS
        content = f"""

<div class="card">

    <h2>Product Search</h2>

    <form method="GET">

        <label>Search</label>

        <input
            name="q"
            value="{q}"
            placeholder="Search products..."
        >

        <button>
            Search
        </button>

    </form>

</div>


<div class="card">

    <h3>
        Search results for: {q}
    </h3>

    <table>

        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Category</th>
            <th>Price</th>
        </tr>

        {results}

    </table>

</div>

"""

        html_response(
            self,
            page(
                "Search",
                content
            )
        )


    # ========================================================
    # USER
    # ========================================================

    def user(self, params):

        username = params.get(
            "username",
            [""]
        )[0]


        # INTENTIONALLY VULNERABLE SQL

        query = f"""
            SELECT id, username, email, role, secret
            FROM users
            WHERE username = '{username}'
        """


        try:

            cursor.execute(
                query
            )

            rows = cursor.fetchall()

        except sqlite3.Error as exc:

            body = f"""
            Database error:

            {exc}

            Query:

            {query}
            """

            text_response(
                self,
                body,
                500
            )

            return


        output = ""


        for row in rows:

            # Sensitive data intentionally exposed.

            output += f"""
            <div class="card">

                <h3>
                    User #{row["id"]}
                </h3>

                <p>
                    Username:
                    {row["username"]}
                </p>

                <p>
                    Email:
                    {row["email"]}
                </p>

                <p>
                    Role:
                    {row["role"]}
                </p>

                <p>
                    Secret:
                    {row["secret"]}
                </p>

            </div>
            """


        if not output:

            output = """
            <div class="danger">
                No user found.
            </div>
            """


        # Reflected XSS intentionally.

        content = f"""

<div class="card">

    <h2>User Lookup</h2>

    <form>

        <input
            name="username"
            value="{username}"
            placeholder="Username"
        >

        <button>
            Search
        </button>

    </form>

</div>

<div class="card">

    Searching for:
    <strong>{username}</strong>

</div>

{output}

"""

        html_response(
            self,
            page(
                "User Lookup",
                content
            )
        )


    # ========================================================
    # PRODUCT
    # ========================================================

    def product(self, params):

        product_id = params.get(
            "id",
            ["1"]
        )[0]


        # INTENTIONALLY VULNERABLE

        query = f"""
            SELECT *
            FROM products
            WHERE id = {product_id}
        """


        try:

            cursor.execute(
                query
            )

            row = cursor.fetchone()

        except sqlite3.Error as exc:

            body = f"""
            Product database error:

            {exc}

            Query:
                {query}
            """

            text_response(
                self,
                body,
                500
            )

            return


        if row:

            content = f"""

<div class="card">

    <h2>
        {row["name"]}
    </h2>

    <p>
        Category: {row["category"]}
    </p>

    <p>
        Price: ${row["price"]}
    </p>

    <p>
        Description: {row["description"]}
    </p>

    <p>
        Stock: {row["stock"]}
    </p>

</div>

"""

        else:

            content = """
            <div class="danger">
                Product not found.
            </div>
            """


        html_response(
            self,
            page(
                "Product",
                content
            )
        )


    # ========================================================
    # PRODUCTS
    # ========================================================

    def products(self, params):

        category = params.get(
            "category",
            [""]
        )[0]


        if category:

            # INTENTIONALLY VULNERABLE

            query = f"""
                SELECT *
                FROM products
                WHERE category = '{category}'
            """

        else:

            query = """
                SELECT *
                FROM products
            """


        try:

            cursor.execute(
                query
            )

            rows = cursor.fetchall()

        except sqlite3.Error as exc:

            text_response(
                self,
                f"""
Product database error:

{exc}

Query:

{query}
                """,
                500
            )

            return


        rows_html = ""


        for row in rows:

            rows_html += f"""
            <tr>

                <td>
                    {row["id"]}
                </td>

                <td>
                    <a href="/product?id={row["id"]}">
                        {row["name"]}
                    </a>
                </td>

                <td>
                    {row["category"]}
                </td>

                <td>
                    ${row["price"]}
                </td>

                <td>
                    {row["stock"]}
                </td>

            </tr>
            """


        content = f"""

<div class="card">

    <h2>Products</h2>

    <form>

        <label>
            Category
        </label>

        <input
            name="category"
            value="{category}"
            placeholder="electronics"
        >

        <button>
            Filter
        </button>

    </form>

</div>


<div class="card">

<table>

<tr>

<th>ID</th>
<th>Name</th>
<th>Category</th>
<th>Price</th>
<th>Stock</th>

</tr>

{rows_html}

</table>

</div>

"""

        html_response(
            self,
            page(
                "Products",
                content
            )
        )


    # ========================================================
    # PROFILE
    # ========================================================

    def profile(self, params):

        user_id = params.get(
            "id",
            ["1"]
        )[0]


        # INTENTIONALLY VULNERABLE SQL

        query = f"""
            SELECT *
            FROM users
            WHERE id = {user_id}
        """


        try:

            cursor.execute(
                query
            )

            user = cursor.fetchone()

        except sqlite3.Error as exc:

            text_response(
                self,
                f"""
Profile database error:

{exc}

Query:

{query}
                """,
                500
            )

            return


        if not user:

            html_response(
                self,
                page(
                    "Profile",
                    "<div class='danger'>User not found.</div>"
                ),
                404
            )

            return


        # Intentionally unsafe output.

        content = f"""

<div class="card">

    <h2>
        Profile
    </h2>

    <p>
        ID: {user["id"]}
    </p>

    <p>
        Username:
        {user["username"]}
    </p>

    <p>
        Email:
        {user["email"]}
    </p>

    <p>
        Role:
        {user["role"]}
    </p>

    <p>
        Secret:
        {user["secret"]}
    </p>

</div>

"""

        html_response(
            self,
            page(
                "Profile",
                content
            )
        )


    # ========================================================
    # LOGIN PAGE
    # ========================================================

    def login_page(self):

        content = """

<div class="card">

    <h2>Login</h2>

    <form method="POST">

        <label>
            Username
        </label>

        <input
            name="username"
            placeholder="Username"
        >


        <label>
            Password
        </label>

        <input
            type="password"
            name="password"
            placeholder="Password"
        >


        <button>
            Login
        </button>

    </form>

</div>

"""

        html_response(
            self,
            page(
                "Login",
                content
            )
        )


    # ========================================================
    # LOGIN
    # ========================================================

    def login(self, params):

        username = params.get(
            "username",
            [""]
        )[0]

        password = params.get(
            "password",
            [""]
        )[0]


        # INTENTIONALLY VULNERABLE SQL

        query = f"""
            SELECT *
            FROM users
            WHERE username = '{username}'
            AND password = '{password}'
        """


        try:

            cursor.execute(
                query
            )

            user = cursor.fetchone()

        except sqlite3.Error as exc:

            text_response(
                self,
                f"""
Login database error:

{exc}

Query:

{query}
                """,
                500
            )

            return


        if user:

            content = f"""

<div class="card">

    <h2>
        Login successful
    </h2>

    <p>
        Welcome {user["username"]}
    </p>

    <p>
        Role:
        {user["role"]}
    </p>

    <p>
        Secret:
        {user["secret"]}
    </p>

</div>

"""

            html_response(
                self,
                page(
                    "Login Success",
                    content
                )
            )

        else:

            html_response(
                self,
                page(
                    "Login Failed",
                    """
                    <div class="danger">
                        Invalid username or password.
                    </div>
                    """
                ),
                401
            )


    # ========================================================
    # API USERS
    # ========================================================

    def api_users(self, params):

        name = params.get(
            "name",
            [""]
        )[0]


        # INTENTIONALLY VULNERABLE

        query = f"""
            SELECT id, username, email, role, secret
            FROM users
            WHERE username LIKE '%{name}%'
        """


        try:

            cursor.execute(
                query
            )

            rows = cursor.fetchall()

        except sqlite3.Error as exc:

            json_response(
                self,
                {
                    "error": str(exc),
                    "query": query
                },
                500
            )

            return


        data = []


        for row in rows:

            data.append(
                dict(row)
            )


        json_response(
            self,
            {
                "count": len(data),
                "users": data
            }
        )


    # ========================================================
    # API PRODUCTS
    # ========================================================

    def api_products(self, params):

        search = params.get(
            "search",
            [""]
        )[0]


        # INTENTIONALLY VULNERABLE

        query = f"""
            SELECT *
            FROM products
            WHERE name LIKE '%{search}%'
               OR description LIKE '%{search}%'
        """


        try:

            cursor.execute(
                query
            )

            rows = cursor.fetchall()

        except sqlite3.Error as exc:

            json_response(
                self,
                {
                    "error": str(exc),
                    "query": query
                },
                500
            )

            return


        products = [
            dict(row)
            for row in rows
        ]


        json_response(
            self,
            {
                "count": len(products),
                "products": products
            }
        )


    # ========================================================
    # ADMIN USERS
    # ========================================================

    def admin_users(self, params):

        sort = params.get(
            "sort",
            ["id"]
        )[0]


        # INTENTIONALLY VULNERABLE:
        # SQL ORDER BY injection.

        query = f"""
            SELECT id, username, email, role
            FROM users
            ORDER BY {sort}
        """


        try:

            cursor.execute(
                query
            )

            rows = cursor.fetchall()

        except sqlite3.Error as exc:

            text_response(
                self,
                f"""
Admin SQL error:

{exc}

Query:

{query}
                """,
                500
            )

            return


        rows_html = ""


        for row in rows:

            rows_html += f"""
            <tr>

                <td>{row["id"]}</td>

                <td>{row["username"]}</td>

                <td>{row["email"]}</td>

                <td>{row["role"]}</td>

            </tr>
            """


        content = f"""

<div class="card">

    <h2>Admin User Management</h2>

    <p>
        Sort by:
        <code>{sort}</code>
    </p>

    <table>

        <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Email</th>
            <th>Role</th>
        </tr>

        {rows_html}

    </table>

</div>

"""

        html_response(
            self,
            page(
                "Admin Users",
                content
            )
        )


    # ========================================================
    # COMMENTS
    # ========================================================

    def comments(self):

        cursor.execute(
            """
            SELECT *
            FROM comments
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()


        comments_html = ""


        for row in rows:

            # INTENTIONALLY STORED XSS

            comments_html += f"""

            <div class="card">

                <strong>
                    {row["username"]}
                </strong>

                <p>
                    {row["comment"]}
                </p>

                <small>
                    {row["created_at"]}
                </small>

            </div>

            """


        content = f"""

<div class="card">

    <h2>Comments</h2>

    <form method="POST"
          action="/comments/add">

        <label>
            Username
        </label>

        <input
            name="username"
            value="guest"
        >


        <label>
            Comment
        </label>

        <textarea
            name="comment"
            rows="5"
        ></textarea>


        <button>
            Add Comment
        </button>

    </form>

</div>


<h2>Recent Comments</h2>

{comments_html}

"""

        html_response(
            self,
            page(
                "Comments",
                content
            )
        )


    # ========================================================
    # ADD COMMENT
    # ========================================================

    def add_comment(self, params):

        username = params.get(
            "username",
            ["guest"]
        )[0]

        comment = params.get(
            "comment",
            [""]
        )[0]


        # Stored directly.

        cursor.execute(
            """
            INSERT INTO comments
            (username, comment)
            VALUES (?, ?)
            """,
            (
                username,
                comment
            )
        )

        conn.commit()


        # Redirect back.

        self.send_response(302)

        self.send_header(
            "Location",
            "/comments"
        )

        self.end_headers()


    # ========================================================
    # FEEDBACK
    # ========================================================

    def feedback(self):

        cursor.execute(
            """
            SELECT *
            FROM feedback
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()


        feedback_html = ""


        for row in rows:

            # INTENTIONALLY STORED XSS

            feedback_html += f"""

            <div class="card">

                <h3>
                    {row["name"]}
                </h3>

                <p>
                    {row["message"]}
                </p>

                <small>
                    {row["email"]}
                </small>

            </div>

            """


        content = f"""

<div class="card">

    <h2>Feedback</h2>

    <form method="POST">

        <label>
            Name
        </label>

        <input name="name">


        <label>
            Email
        </label>

        <input name="email">


        <label>
            Message
        </label>

        <textarea
            name="message"
            rows="5"
        ></textarea>


        <button>
            Submit Feedback
        </button>

    </form>

</div>


<h2>Previous Feedback</h2>

{feedback_html}

"""

        html_response(
            self,
            page(
                "Feedback",
                content
            )
        )


    # ========================================================
    # ADD FEEDBACK
    # ========================================================

    def add_feedback(self, params):

        name = params.get(
            "name",
            [""]
        )[0]

        email = params.get(
            "email",
            [""]
        )[0]

        message = params.get(
            "message",
            [""]
        )[0]


        cursor.execute(
            """
            INSERT INTO feedback
            (name, email, message)
            VALUES (?, ?, ?)
            """,
            (
                name,
                email,
                message
            )
        )

        conn.commit()


        self.send_response(302)

        self.send_header(
            "Location",
            "/feedback"
        )

        self.end_headers()


    # ========================================================
    # OPEN REDIRECT
    # ========================================================

    def redirect(self, params):

        destination = params.get(
            "next",
            ["/"]
        )[0]


        # INTENTIONALLY VULNERABLE OPEN REDIRECT

        self.send_response(302)

        self.send_header(
            "Location",
            destination
        )

        self.end_headers()


    # ========================================================
    # DEBUG
    # ========================================================

    def debug(self):

        content = f"""

<div class="card">

    <h2>Debug Information</h2>

    <pre>

Python:
{os.sys.version}

Platform:
{os.name}

Working Directory:
{os.getcwd()}

Database:
{os.path.abspath(DB_FILE)}

Server:
{HOST}:{PORT}

Client:
{self.client_address}

User-Agent:
{self.headers.get("User-Agent", "")}

    </pre>

</div>

<div class="danger">

    Debug information should not normally be exposed
    by a production application.

</div>

"""

        html_response(
            self,
            page(
                "Debug",
                content
            )
        )


    # ========================================================
    # HEADERS
    # ========================================================

    def headers(self):

        content = """

<div class="card">

    <h2>HTTP Security Headers</h2>

    <p>
        This endpoint intentionally demonstrates
        an application with weak HTTP security headers.
    </p>

    <ul>

        <li>
            Content-Security-Policy: Missing
        </li>

        <li>
            X-Frame-Options: Missing
        </li>

        <li>
            X-Content-Type-Options: Missing
        </li>

        <li>
            Strict-Transport-Security: Missing
        </li>

        <li>
            Referrer-Policy: Missing
        </li>

    </ul>

</div>

"""

        html_response(
            self,
            page(
                "Headers",
                content
            )
        )


    # ========================================================
    # LOGGING
    # ========================================================

    def log_request(self, path):

        user_agent = self.headers.get(
            "User-Agent",
            ""
        )


        try:

            cursor.execute(
                """
                INSERT INTO logs
                (event, ip, user_agent)
                VALUES (?, ?, ?)
                """,
                (
                    "HTTP GET " + path,
                    self.client_address[0],
                    user_agent
                )
            )

            conn.commit()

        except Exception:
            pass


    # ========================================================
    # ERROR HANDLING
    # ========================================================

    def server_error(self, exc):

        # Intentionally verbose.

        body = f"""
<!DOCTYPE html>

<html>

<head>
<title>Internal Server Error</title>
</head>

<body>

<h1>Internal Server Error</h1>

<h2>Exception</h2>

<pre>
{exc}
</pre>

<h2>Traceback</h2>

<pre>
{traceback.format_exc()}
</pre>

</body>

</html>
"""


        self.send_response(500)

        self.send_header(
            "Content-Type",
            "text/html"
        )

        self.end_headers()

        self.wfile.write(
            body.encode()
        )


    # ========================================================
    # 404
    # ========================================================

    def not_found(self):

        html_response(
            self,
            page(
                "404",
                """
                <div class="danger">

                    <h2>
                        404 - Page Not Found
                    </h2>

                    <p>
                        The requested resource does not exist.
                    </p>

                </div>
                """
            ),
            404
        )


    # ========================================================
    # QUIET SERVER LOGGING
    # ========================================================

    def log_message(self, format, *args):

        # Keep scanner output readable.

        pass


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("        VULNERABLE WEB SECURITY LAB")
    print("=" * 70)
    print()
    print("WARNING: INTENTIONALLY VULNERABLE")
    print()
    print(f"Listening ONLY on: http://{HOST}:{PORT}")
    print()
    print("Main endpoints:")
    print()
    print("  /")
    print("  /search?q=test")
    print("  /user?username=admin")
    print("  /product?id=1")
    print("  /products?category=electronics")
    print("  /profile?id=1")
    print("  /login")
    print("  /api/users?name=admin")
    print("  /api/products?search=laptop")
    print("  /admin/users?sort=username")
    print("  /comments")
    print("  /feedback")
    print("  /redirect?next=/")
    print("  /debug")
    print("  /headers")
    print()
    print("SQL Injection:")
    print("  /user")
    print("  /search")
    print("  /product")
    print("  /products")
    print("  /profile")
    print("  /login")
    print("  /api/users")
    print("  /api/products")
    print("  /admin/users")
    print()
    print("XSS:")
    print("  /search")
    print("  /user")
    print("  /profile")
    print("  /comments")
    print("  /feedback")
    print()
    print("=" * 70)
    print()


    init_database()


    server = HTTPServer(
        (HOST, PORT),
        Handler
    )


    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print("\nStopping server...")

    finally:

        server.server_close()
        conn.close()