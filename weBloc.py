import sqlite3
import socket
import threading
import time
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
from flask import Flask, render_template_string, request, redirect, url_for, session, Response
import os

# Setup constants and configurations
BLOCKED_IP = "127.0.0.1"
DATABASE = 'allowed_domains.db'
PASSWORD = os.getenv("ADMIN_PASSWORD", "securepass")  # Use environment variable for security
CACHE_TTL = 30  # Shorter TTL for dynamic IPs

app = Flask(__name__)
app.secret_key = os.urandom(24)

def create_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS allowed_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    ip_address TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS dynamic_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def add_allowed_domain(domain, ip_address, dynamic=False):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    if dynamic:
        c.execute('INSERT INTO dynamic_domains (domain) VALUES (?)', (domain,))
    else:
        c.execute('INSERT INTO allowed_domains (domain, ip_address) VALUES (?, ?)', (domain, ip_address))
    conn.commit()
    conn.close()

def remove_allowed_domain(domain):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('DELETE FROM allowed_domains WHERE domain = ?', (domain,))
    c.execute('DELETE FROM dynamic_domains WHERE domain = ?', (domain,))
    conn.commit()
    conn.close()

def get_allowed_domains():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT domain, ip_address FROM allowed_domains')
    allowed = {domain.lower(): ip for domain, ip in c.fetchall()}
    c.execute('SELECT domain FROM dynamic_domains')
    dynamic = [domain[0].lower() for domain in c.fetchall()]
    conn.close()
    return allowed, dynamic

def resolve_dynamic_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return BLOCKED_IP  # If resolution fails, return blocked IP

def handle_dns_request(data, addr, sock):
    request = DNSRecord.parse(data)
    qname = str(request.q.qname).strip('.').lower()
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    allowed_domains, dynamic_domains = get_allowed_domains()
    
    if qname in dynamic_domains:
        ip_address = resolve_dynamic_ip(qname)
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip_address), ttl=CACHE_TTL))
    elif qname in allowed_domains:
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(allowed_domains[qname]), ttl=300))
    else:
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(BLOCKED_IP), ttl=300))

    sock.sendto(reply.pack(), addr)

def run_dns_server():
    print("Starting DNS Filtering Server...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        data, addr = sock.recvfrom(512)
        handle_dns_request(data, addr, sock)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == "admin" and password == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for("allowed_domains"))
        return "Invalid credentials."
    return render_template_string("""
    <form method="POST">
        Username: <input type="text" name="username" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Login">
    </form>
    """)

@app.route("/allowed-domains", methods=["GET", "POST"])
def allowed_domains():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for("login"))

    if request.method == "POST":
        domain = request.form["domain"].strip().lower()
        ip_address = request.form.get("ip_address", "").strip()
        dynamic = 'dynamic' in request.form
        add_allowed_domain(domain, ip_address, dynamic)
        return redirect(url_for("allowed_domains"))
    
    if request.args.get('remove'):
        remove_allowed_domain(request.args.get('remove').strip().lower())
        return redirect(url_for("allowed_domains"))
    
    allowed, dynamic = get_allowed_domains()
    return render_template_string("""
    <h1>Allowed Domains</h1>
    <table>
        <tr><th>Domain</th><th>IP Address</th><th>Type</th><th>Action</th></tr>
        {% for domain, ip in allowed.items() %}
        <tr><td>{{ domain }}</td><td>{{ ip }}</td><td>Static</td><td><a href="?remove={{ domain }}">Remove</a></td></tr>
        {% endfor %}
        {% for domain in dynamic %}
        <tr><td>{{ domain }}</td><td>Dynamic</td><td>Dynamic</td><td><a href="?remove={{ domain }}">Remove</a></td></tr>
        {% endfor %}
    </table>
    <h2>Add Domain</h2>
    <form method="POST">
        Domain: <input type="text" name="domain" required><br>
        IP Address (if static): <input type="text" name="ip_address"><br>
        <input type="checkbox" name="dynamic"> Dynamic Domain<br>
        <input type="submit" value="Add">
    </form>
    <a href="/login">Logout</a>
    """, allowed=allowed, dynamic=dynamic)

if __name__ == "__main__":
    create_db()
    threading.Thread(target=run_dns_server, daemon=True).start()
    app.run(host="0.0.0.0", port=80)