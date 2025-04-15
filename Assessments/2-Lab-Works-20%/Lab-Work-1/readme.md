# Network Protocol Vulnerabilities Lab

## A. Objective

The goal of this lab is to explore the vulnerabilities of common network protocols (FTP, TELNET, SSH, HTTP) by performing brute force attacks to recover passwords and then using those credentials to sniff network traffic.  
You will also analyze the security of these protocols and propose mitigation strategies.

---

## B. Lab Tasks

### 1. Enumerate the Vulnerable VM to Discover Usernames
- Identify potential usernames for brute force attacks.
- Document the usernames found.

### 2. Perform Brute Force Attacks

#### 2.1. FTP, TELNET, and SSH
- Use tools like **Hydra**, **Medusa**, or **NetExec** to perform brute force attacks against:
  - FTP
  - TELNET
  - SSH

#### 2.2. HTTP
- Use **Burp Intruder** to automate brute force attacks against an HTTP login page.
- Configure Intruder to test a list of usernames and passwords.
- Analyze the results to identify successful logins.

### 3. Sniff Network Traffic
- Use the recovered credentials to log in to the respective services.
- Use **Wireshark** or **tcpdump** to capture and analyze network traffic during the session.
- Identify which protocols transmit data in plaintext and which use encryption.
- Provide evidence (e.g., screenshots) to prove which protocols are secure and which are not.

### 4. Analyze Problems Encountered
- Document any issues during brute force attacks (e.g., rate limiting, protocol-specific challenges).
- Explain how you resolved these issues.

### 5. Propose Mitigation Strategies
- For each vulnerable protocol, propose a secure alternative.
- Explain how these alternatives mitigate the vulnerabilities.

### 6. Write a Walkthrough
- Document the entire process in a walkthrough format.
- Include:
  - Tools used
  - Commands executed
  - Screenshots of key steps
  - Analysis of results
  - Mitigation strategies

---

## C. Deliverables

- **Walkthrough Document:** A detailed markdown file documenting your process, results, and analysis.
- **Evidence:** Screenshots of brute force attacks, packet captures, and successful logins.
- **GitHub Repository:** This repository with the walkthrough and evidence pushed here.
- **Demo and Debrief:** A 5–15 minute live demo and presentation of your findings.

---

## D. Demo and Debrief

Each student will perform a **5–15 minute** live demo of their lab work, including:
- A brief explanation of the tools and techniques used.
- A demonstration of the brute force attack and sniffing process.
- A summary of findings and mitigation strategies.

The debrief will assess your understanding of the topic and enhance your public speaking and presentation skills.

---

## E. Submission Instructions

- Create a public GitHub repository (✅ this repository).
- Push your walkthrough (in Markdown format) and evidence (screenshots) here.
- Submit the repository link to your instructor.
- Be prepared to deliver a live demo and debrief during the lab session.

---
