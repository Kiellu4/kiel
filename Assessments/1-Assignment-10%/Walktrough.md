# 🛡️ Network Protocol Vulnerability Lab - Walkthrough

## 📌 Objective
The purpose of this lab is to simulate brute force attacks against common network services (**FTP**, **TELNET**, **SSH**, and **HTTP**), analyze the security of these protocols, capture and inspect network traffic, and propose security mitigations.

---

## 🖥️ Lab Environment Setup
- **Attacker VM:** Kali Linux 2024.4
- **Target VM:** Vulnerable Linux VM (Metasploitable2 / custom)
- **Tools Used:** Hydra, Burp Suite, Wireshark,

---

# 🧾 Task 1: Enumerate the Target

## 🎯 Goal
Identify valid usernames on the target VM.

## 1.1 Nmap scan
Performed an initial scan to discover open services.

---

## 🛠️ Commands Used
```bash
nmap -p 21,23,22,80 <target-ip> 
```

![image](https://github.com/user-attachments/assets/3003bcc5-bfd0-4b8f-b4e4-77baba25b8c5)

---

## 1.2 Enum4linux Enumeration
Since ports (21,23,22,80) are open, used enum4linux to gather more usernames.

---

## 🛠️ Commands Used
```bash
enum4linux -a <target-ip> 
```
![image](https://github.com/user-attachments/assets/d3aa5613-9725-45dc-9d5c-d2f50fb3ad5e)
![image](https://github.com/user-attachments/assets/2fd2d4d5-60fe-412f-b145-e07f3199bfc9)

---

# 🔐 Task 2: Brute Force Attacks

## ✅ Preparation

Before conducting brute-force attacks, prepare the following:

- **Username list** (`userlist.txt`)
- **Password list** (`passlist.txt`)

You can either:

- Use common lists available in Kali Linux, such as `/usr/share/wordlists/rockyou.txt`
- Or manually create a small custom list for testing:

```bash
echo -e "admin\nmsfadmin\nanonymous\nuser\ntest" > userlist.txt
echo -e "1234\nmsfadmin\nftp123\nadmin\npassword" > passlist.txt
```

---

## 🔹 2.1 FTP Brute Force with Hydra
Command to attack FTP:
```bash
hydra -L userlist.txt -P passlist.txt ftp://<TARGET_IP> -V
```
![image](https://github.com/user-attachments/assets/464596a3-72a8-4ecc-801d-82f4ed8cc9ae)

## 🔹 2.2 Telnet Brute Force with Hydra
Command to attack Telnet:
```bash
hydra -L userlist.txt -P passlist.txt telnet://<TARGET_IP> -V
```
![image](https://github.com/user-attachments/assets/0d3223f5-d120-408c-ab08-b0b93d67127c)

## 🔹 2.3 SSH Brute Force with NetExec
Command to attack SSH:
```bash
nxc ssh <TARGET_IP> -u userlist.txt -p passlist.txt
```
![Screenshot 2025-04-10 213136](https://github.com/user-attachments/assets/b9a82523-a2a4-4619-8c0e-3434a899d9f1)

## 🔹 2.4 HTTP Login Brute Force Using Burp Suite Intruder

### Step 1: Launch Burp’s Browser
- Open **Burp Suite**.
- Go to `Proxy > Intercept`.
- Ensure **Intercept is ON**.
- Click **Open Browser** to start Burp’s embedded browser.

### Step 2: Capture Login Request
- Visit the login page (e.g., `http://<TARGET_IP>/login`) using Burp’s browser.
- Enter any dummy username and password to trigger a login attempt.
- Burp will capture the HTTP request automatically.

### Step 3: Forward the Request
- In Burp’s `Proxy > Intercept` tab, click **Forward** to send the intercepted request.
- If multiple requests are caught, continue forwarding until the page loads.

### Step 4: Disable Intercept
- Switch **Intercept is OFF** so that future browser requests are not paused.

### Step 5: Send to Intruder
- In **Proxy > HTTP History**, find the POST request to the login page.
- Right-click the request → **Send to Intruder**.

### Step 6: Configure the Intruder Attack
- In **Intruder** tab:
  - Set **Attack Type** to **Cluster Bomb**.
  - Highlight and mark the username and password fields as **payload positions**.

### Step 7: Load Payload Lists
- Payload Set 1: Load `userlist.txt` (usernames).
- Payload Set 2: Load `passlist.txt` (passwords).

### Step 8: Start Attack
- Click **Start Attack**.
- Monitor for:
  - Changes in **Status Codes**.
  - Differences in **Response Length**.
  - Presence of success indicators (e.g., `Welcome`, dashboard redirects).

![image](https://github.com/user-attachments/assets/92f85079-5876-4875-882b-4a8b3bb9c1e1)
![image](https://github.com/user-attachments/assets/250a4923-292c-4ae5-b71d-a0daa35b4d97)
![image](https://github.com/user-attachments/assets/47249397-aa3d-4f59-8071-fd5ba68888c1)
![image](https://github.com/user-attachments/assets/5c3fd87b-a8a9-42b8-819c-5ddc41cba45d)
![image](https://github.com/user-attachments/assets/13994a4e-4eb3-4c36-89c1-906e18b9ac4e)

> 🔎 **Note:** Successful logins often have different response lengths or status codes like 302 (redirect).

---

## ⚠️ Common Problems and How to Fix Them

| Problem                        | Cause                         | Solution                                  |
| ------------------------------ | ----------------------------- | ----------------------------------------- |
| Too many failed login attempts | Account lockout/ Rate limiting| Add delay or reduce threads (`-t 1`) |
|CAPTCHA on login form protections| HTTP brute force fails       | May require manual testing or CAPTCHA bypass techniques |
| SSH protection (e.g., fail2ban)| IP gets blocked after failures| Rotate IPs with VPN or proxychains        |

---

# 📡 Task 3: Sniffing Network Traffic

Captured network traffic during login attempts with cracked credentials.

**Tool Used:** Wireshark

---

## 🔹 Steps
1. Open Wireshark.
> **Command:** 
```bash
sudo wireshark
```
2. Start capture on the network interface connected to the target.
3. Apply filters:
  - FTP: tcp.port == 21
  - TELNET: tcp.port == 23
  - SSH: tcp.port == 22
  - HTTP: tcp.port == 80
> **Command:** Combine all tcp.port in one filter.
```bash
tcp.port == 21 || tcp.port == 22 || tcp.port == 23 || tcp.port == 80
```
4. Identify unencrypted traffic containing credentials.

## 🔹 Screenshots
- **FTP sniffed:**
  > 

- **TELNET sniffed:**
  > 

- **SSH encrypted:**
  >

---

**Tool Used:** tcpdump

---
## 🔹 Steps
> **Command:** to use tcpdump and gather port 21,22,23,80 in capture.pcap.
```bash
sudo tcpdump -i eth0 port 21 or port 23 or port 22 or port 80 -w capture.pcap
 ```
Analyze capture.pcap in Wireshark.

## 🔹 Observations

| Protocol | Encryption | Credentials Visible? |
| -------- | ---------- | --------------------- |
| FTP      | ❌ No       | ✅ Yes (cleartext)     |
| TELNET   | ❌ No       | ✅ Yes (cleartext)     |
| SSH      | ✅ Yes      | ❌ No (encrypted)      |
| HTTP     | ❌ No       | ✅ Yes (cleartext)     |

---

## 🔹 Screenshots

- **FTP sniffed:**
  > 

- **TELNET sniffed:**
  > 

- **SSH encrypted:**
  > 

---

# ⚠️ Task 4: Problems Encountered

| Problem                         | Solution                                         |
| -------------------------------- | ------------------------------------------------ |
| SMB enumeration slow            | Used `-v` (verbose) option to monitor progress   |
| SSH brute-force blocked quickly | Used `-t 4 -w 5` flags in Hydra to slow attack    |
| HTTP login page rate-limited     | Introduced delay between Burp Intruder requests  |

---

# 🛡️ Task 5: Mitigation Strategies

| Protocol | Vulnerability            | Mitigation                     | Secure Alternative         |
| -------- | ------------------------- | ------------------------------- | --------------------------- |
| FTP      | Plaintext transmission     | Use FTPS or SFTP                | ✅ FTPS / SFTP               |
| TELNET   | Plaintext transmission     | Disable TELNET, use SSH         | ✅ SSH                      |
| HTTP     | No encryption              | Use HTTPS with SSL/TLS          | ✅ HTTPS                    |
| SMB      | Weak usernames             | Harden SMB settings, disable guest access | ✅ Enforce SMB Signing |
| Passwords | Easily brute-forced        | Strong password policies + MFA  | 🔒 Strong Passwords + Account Lockout |

---

# 📝 Conclusion

- Enumerated usernames using **Nmap** and **enum4linux**.
- Brute-forced login credentials on **FTP**, **TELNET**, **SSH**, and **HTTP**.
- Captured and inspected cleartext credentials via **Wireshark**.
- Verified that **SSH** traffic is encrypted.
- Suggested mitigation strategies to secure vulnerable services.

---
