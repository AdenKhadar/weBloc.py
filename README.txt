# DNS Filtering Server with Web Management

## Description
This project is a **DNS filtering server** with a web-based management interface. It allows administrators to **whitelist specific domains** while blocking all others by resolving them to `127.0.0.1`. It supports both **static and dynamic IP domains**.

### Features:
- **DNS Server** to filter and resolve whitelisted domains.
- **Dynamic Domain Support**: Resolves domains with changing IP addresses.
- **Web-based Admin Panel**: Add/remove domains dynamically.
- **SQLite Database** for domain storage.
- **User Authentication** with admin login.

### Issues and Limitations:
1. **Dynamic IP Address Resolution Problem**:
   - Dynamic domains rely on `socket.gethostbyname()`, which can cause **intermittent failures** if the DNS resolution fails or if the IP changes too quickly.
   - Cached IPs (TTL: 30s) might **not update fast enough**.
   - If a site’s IP changes frequently, it may become temporarily inaccessible.

2. **Security Concerns**:
   - The admin password is stored in an **environment variable** but defaults to `securepass`, which is **unsafe**.
   - The web interface **lacks encryption (HTTPS)**.
   - No rate-limiting or brute-force protection in login authentication.

3. **Potential DNS Hijacking Risks**:
   - The DNS server operates on port **53 (UDP)**, which is a common target for **DNS hijacking and spoofing attacks**.
   - There’s **no validation on incoming DNS requests**.

### Help Needed
I need assistance in resolving the known issues, particularly:
- Improving **dynamic DNS resolution** to handle frequent IP changes more reliably.
- Enhancing **security measures**, such as adding HTTPS, stronger authentication, and brute-force protection.
- Implementing **better DNS validation** to mitigate hijacking risks.

---

## Installation and Setup

### Prerequisites:
- Python 3.x
- Required dependencies: `sqlite3`, `socket`, `dnslib`, `flask`

### Steps to Run:
1. **Install dependencies:**
   ```bash
   pip install dnslib flask
   ```

2. **Set up the database:**
   ```bash
   python -c "import sqlite3; sqlite3.connect('allowed_domains.db').close()"
   ```

3. **Start the DNS server and web app:**
   ```bash
   python script.py
   ```
   - The **DNS server** runs on `0.0.0.0:53`.
   - The **Web Admin Panel** runs on `http://0.0.0.0:80`.

4. **Access the Admin Panel:**
   - Open `http://your-server-ip/allowed-domains` in your browser.
   - Default **login credentials**: 
     - **Username**: `admin`
     - **Password**: Set via `ADMIN_PASSWORD` environment variable.

5. **Adding Domains:**
   - Static domains require an IP address.
   - Dynamic domains (for websites with changing IPs) **do not require an IP** but may have resolution issues.

---

## Troubleshooting

### 1. DNS Requests Not Resolving?
- Ensure port **53 UDP is not blocked** by the firewall:
  ```bash
  sudo ufw allow 53/udp
  ```
- Run the script with admin/root privileges (`sudo python script.py`).
- Check if another process is **already using port 53**:
  ```bash
  sudo lsof -i :53
  ```

### 2. Dynamic IP Issues
- Sites with **rapidly changing IPs** may become inaccessible due to caching.
- Try reducing the TTL further (e.g., 10s) in `CACHE_TTL = 30`.

### 3. Web Interface Issues
- Make sure **Flask is running** on port 80.
- If the web page is inaccessible, check logs for Flask errors.

---

## Future Improvements
- **Implement HTTPS** for secure admin access.
- **Improve dynamic DNS handling** to avoid frequent failures.
- **Add logging and monitoring** for better debugging.

---

## License
MIT License
