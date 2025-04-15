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

![image](https://github.com/user-attachments/assets/903de471-2a8b-4ab8-809c-e6a17351adbc)

### Step 2: Search Ip Address Metasploitable2
- Open Firefox browser.
- Search the <TARGET_IP> and click Enter.
- Then, click the DVWA section.
- Fill the Username = 'Admin' and Password = 'Password'.
- At the left, choose Brute Force.
- Fill anything to the Username and Password (Example: Username=aaa and Password=aaa).

![image](https://github.com/user-attachments/assets/38f00c6b-9bec-45e0-b9d8-6926866fc284)
![image](https://github.com/user-attachments/assets/fa27b23c-2c67-4436-b676-f88cf55ab4b3)
![image](https://github.com/user-attachments/assets/ff3072a6-2c80-45bf-8b6a-a07c3cfe6e4d)

### Step 3: Forward the Request
- In Burp’s `Proxy > Intercept` tab, Everytime the intercept get request keep click **Forward** to send the intercepted request.
- If multiple requests are caught, continue forwarding until the page loads.
- Go to `Proxy > HTTP history` tab, and find `http://192.168.65.54/dvwa/vulnerabilities/brute/?username=aaa&password=aaa&Login=Login` then right click and choose **Send to Intruder**.

![image](https://github.com/user-attachments/assets/27aba17b-6817-427c-8e4b-419684b89047)

### Step 4: Disable Intercept
- Switch **Intercept is OFF** so that future browser requests are not paused.

![image](https://github.com/user-attachments/assets/f384e277-e41a-4d23-9105-0d203cb00d6e)

### Step 5: Configure the Intruder Attack
- In **Intruder** tab:
  - Set **Attack Type** to **Cluster Bomb**.
  - Highlight and mark the username and password fields as **payload positions**.
  - On the **Payload position**, Load with the file in the with the **Username list** (`userlist.txt`) and **Password list** (`passlist.txt`). (`Example:/usr/share/wordlists`)

![image](https://github.com/user-attachments/assets/b2962371-7934-4a79-90ff-dd05b0adb37d)

### Step 6: Start Attack
- Click **Start Attack**.
- Monitor for:
  - Changes in **Response**.
  - Click the **Render** for visual output.
  - There are `25 request`. So, you need to try and error untuil you find the correct output.
  - If the access successful the output will be `Welcome to the password protected area admin`.
  - If not, the output will be `Username and/or password incorrect`.

![image](https://github.com/user-attachments/assets/3312dc4f-a720-4339-b1a1-db4c4133eac3)
![image](https://github.com/user-attachments/assets/89705868-51e3-41cb-af80-cc513af07cce)
![image](https://github.com/user-attachments/assets/915c2834-0a01-4c65-8111-9d1d6ecce0dd)

---

# 📡 Task 3: Sniffing Network Traffic

Captured network traffic during login attempts with cracked credentials.

**Tool Used:** Wireshark

---

## 🔹 Steps
1. Open Wireshark.
> **Command:** 
```bash
wireshark
```
  - Choose `eth0` for sniffing traffic.
> ![image](https://github.com/user-attachments/assets/1ed5a265-d331-452b-97ad-7ddc0aa411ff)

2. Start capture on the network interface connected to the target for the FTP.
   - (1) FTP command:
```bash
ftp <target-ip> 
```
   - Enter the `Username = msfadmin` and `Password = msfadmin` as we got exploit from brute force attack before.

> ![image](https://github.com/user-attachments/assets/27f207e0-16f9-46ca-b0d4-d9377f1f90bf)

3. Get the FTP packet for FTP.
   - Choose the first one packet that have `FTP` and right click.
   - Go to `Follow` and click `TCP Stream`.
> ![image](https://github.com/user-attachments/assets/18e1ff89-99a4-4991-9578-44e845c4fc92)

4. Identify unencrypted traffic containing credentials for the FTP.
   - **FTP sniffed:**
   - As you can see, the file is not encrypted.

> ![image](https://github.com/user-attachments/assets/234116f3-3afc-47a8-9764-93437bebf2b8)

5. Start capture on the network interface connected to the target for the SSH.
   - (2) SSH command:
```bash
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedKeyTypes=+ssh-rsa <username>@<target-ip> 
```
   - Enter the `Username = msfadmin` and `Password = msfadmin` as we got exploit from brute force attack before.

> ![image](https://github.com/user-attachments/assets/cdd503c0-0aa4-4b2a-ab51-47e538aa65f9)

6. Get the FTP packet for the SSH.
   - Choose the new one packet until last that have `FTP` and right click.
   - For me, I choose packet at `no.78` because packet 1-74 for FTP.
   - Go to `Follow` and click `TCP Stream`.

> ![image](https://github.com/user-attachments/assets/a03564e9-0555-4b55-bbad-b7e10c407053)

7. Identify unencrypted traffic containing credentials for the SSH.
   - **SSH sniffed:**
   - As you can see, the file is encrypted.
     
> ![image](https://github.com/user-attachments/assets/3febb274-a848-4800-9026-0bfb7e6e89bc)

8. Start capture on the network interface connected to the target for the Telnet.
   - (3) Telnet command:
```bash
telnet <target-ip> 
```
   - Enter the `Username = msfadmin` and `Password = msfadmin` as we got exploit from brute force attack before.

> ![image](https://github.com/user-attachments/assets/375398e4-f50b-4907-b557-1fd5d98be295)

9. Get the FTP packet for the SSH.
   - Choose the new one packet until last that have `FTP` and right click.
   - For me, I choose packet at `no.78` because packet 1-74 for FTP.
   - Go to `Follow` and click `TCP Stream`.
  
> ![image](https://github.com/user-attachments/assets/0812d0bd-574a-4268-865a-2447855ead7e)

10. Identify unencrypted traffic containing credentials for the SSH.
   - **Telnet sniffed:**
   - As you can see, the file is not encrypted. 

> ![image](https://github.com/user-attachments/assets/9ff0a3b6-b908-4ce2-8363-f4d4b42100b3)

---

## 🔹 Observations

| Protocol | Encryption | Credentials Visible? |
| -------- | ---------- | --------------------- |
| FTP      | ❌ No       | ✅ Yes (cleartext)     |
| TELNET   | ❌ No       | ✅ Yes (cleartext)     |
| SSH      | ✅ Yes      | ❌ No (encrypted)      |
| HTTP     | ❌ No       | ✅ Yes (cleartext)     |

---

# ⚠️ Task 4: Problems Encountered

| Problem                         | Solution                                         |
| -------------------------------- | ------------------------------------------------ |
| SSH brute-force blocked quickly | Used `-t 4 -w 5` flags in Hydra to slow attack    |
| HTTP login page rate-limited     | Introduced delay between Burp Intruder requests  |

---

# 🛡️ Task 5: Mitigation Strategies

| Protocol | Vulnerability            | Mitigation                     | Secure Alternative         |
| -------- | ------------------------- | ------------------------------- | --------------------------- |
| FTP      | Plaintext transmission     | Use FTPS or SFTP                | ✅ FTPS / SFTP               |
| TELNET   | Plaintext transmission     | Disable TELNET, use SSH         | ✅ SSH                      |
| HTTP     | No encryption              | Use HTTPS with SSL/TLS          | ✅ HTTPS                    |
| SSH      | Weak encryption           | Update latest SSH or limit SSH using (Authorize users) | ✅ Update SSH |
| Passwords | Easily brute-forced       | Strong password policies + MFA  | 🔒 Strong Passwords + Account Lockout |

---

# 📝 Conclusion

- Enumerated usernames using **Nmap** and **enum4linux**.
- Brute-forced login credentials on **FTP**, **TELNET**, **SSH**, and **HTTP**.
- Captured and inspected cleartext credentials via **Wireshark**.
- Verified that **SSH** traffic is encrypted.
- Suggested mitigation strategies to secure vulnerable services.

---
