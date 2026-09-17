# SMTP Username Enumerator

A lightweight Python tool for **SMTP username enumeration** using the `VRFY`, `EXPN`, and `RCPT TO` methods.

Designed for authorized penetration testing, security labs, CTFs, and SMTP security assessments.

## Features

* 🔎 SMTP username enumeration
* 📡 Support for `VRFY`, `EXPN`, and `RCPT TO`
* 🔄 Automatic reconnect after connection loss
* 🛑 Automatic detection of SMTP `421` responses
* ⏳ Adaptive delay when rate limiting is detected
* 🔁 Automatically retries usernames affected by connection errors
* 🧩 Handles `BrokenPipeError`, `ConnectionResetError`, `ConnectionAbortedError`, `TimeoutError`, and socket errors
* 💾 Automatically saves valid usernames
* ⚙️ Configurable target, port, wordlist, method, domain, timeout, delay, and retry count
* 🐍 Python 3 compatible
* 📦 No external Python packages required
* ⏳ Automatic delay and retry when SMTP rate limiting is detected
* 🔁 Automatically resumes enumeration after temporary SMTP throttling
* 🔓 Rate-limit recovery mechanism to bypass enumeration interruption caused by Too Many Requests

---

## Requirements

Python 3:

```bash
python3 --version
```

The script uses only Python standard libraries.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/smtp-user-enumerator.git
```

Enter the directory:

```bash
cd smtp-user-enumerator
```

Make the script executable:

```bash
chmod +x smtp_enum.py
```

Run the script:

```bash
./smtp_enum.py --help
```

Or:

```bash
python3 smtp_enum.py --help
```

---

## Help

```bash
python3 smtp_enum.py --help
```

Available options:

| Option             | Description                   | Default             |
| ------------------ | ----------------------------- | ------------------- |
| `-t`, `--target`   | SMTP server IP/hostname       | Required            |
| `-p`, `--port`     | SMTP port                     | `25`                |
| `-w`, `--wordlist` | Username wordlist             | Required            |
| `-M`, `--method`   | Enumeration method            | `VRFY`              |
| `-D`, `--domain`   | Domain for RCPT               | `inlanefreight.htb` |
| `--timeout`        | Socket timeout                | `10`                |
| `--delay`          | Normal delay between requests | `0`                 |
| `--retry`          | Maximum retry attempts        | `3`                 |
| `-o`, `--output`   | Output file                   | `valid_users.txt`   |

---

# Recommended Workflow

## 1. Check SMTP Port

```bash
nmap -Pn -p25 -sV 10.129.169.159
```

Example:

```text
25/tcp open smtp Postfix smtpd
```

---

## 2. Check SMTP Capabilities

```bash
nmap -Pn -p25 --script smtp-commands 10.129.169.159
```

Look for capabilities such as:

```text
VRFY
EXPN
STARTTLS
```

If `VRFY` is supported, it can be tested for username enumeration.

---

## 3. Manual SMTP Test

Connect:

```bash
nc -nv 10.129.169.159 25
```

Then:

```text
EHLO inlanefreight.htb
```

Test a username:

```text
VRFY robin
```

Example valid response:

```text
252 2.0.0 robin
```

Test an invalid username:

```text
VRFY T876
```

Example:

```text
550 5.1.1 <T876>: Recipient address rejected: User unknown in local recipient table
```

Exit:

```text
QUIT
```

---

# Wordlist

Create a username wordlist:

```bash
nano users.list
```

Example:

```text
root
admin
administrator
robin
john
jennifer
michael
thomas
```

Check the wordlist:

```bash
cat users.list
```

Count usernames:

```bash
wc -l users.list
```

---

# Usage

## VRFY Enumeration

Basic:

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY
```

With custom timeout:

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY --timeout 15
```

With retry:

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY --retry 5
```

With normal delay:

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY --delay 1
```

With custom output:

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY -o valid_users.txt
```

---

# EXPN Enumeration

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M EXPN
```

If the SMTP server does not support `EXPN`, this method may not provide useful results.

---

# RCPT TO Enumeration

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M RCPT -D inlanefreight.htb
```

The tool performs an SMTP transaction similar to:

```text
MAIL FROM:<test@inlanefreight.htb>
RCPT TO:<robin@inlanefreight.htb>
```

---

# Adaptive Rate-Limit Handling

The tool does **not** use a fixed batch size.

Instead, it monitors SMTP responses.

For example:

```text
421 4.7.0 mail1 Error: too many errors
```

The script automatically:

```text
421
 ↓
Detect rate limit
 ↓
Close connection
 ↓
Determine delay
 ↓
Wait
 ↓
Reconnect
 ↓
Retry the same username
```

Example:

```text
[RATE-LIMIT] thomas -> 421 4.7.0 mail1 Error: too many errors
[*] Server requested/indicated slowdown.
[*] Waiting 3 seconds before reconnect...
[+] Reconnected successfully.
[*] Retrying thomas...
```

The script also attempts to detect delay information contained in the server response, such as:

```text
retry after 10 seconds
```

or:

```text
wait 5 seconds
```

If no delay is provided, it uses a default adaptive delay.

---

# Broken Pipe Handling

A `BrokenPipeError` does **not** automatically mean that the username is invalid.

For example:

```text
BrokenPipeError: [Errno 32] Broken pipe
```

usually means the client attempted to write to a connection that the server had already closed.

The tool handles this automatically:

```text
[CONNECTION] jennifer -> BrokenPipeError: [Errno 32] Broken pipe
[*] Waiting 2s...
[+] Reconnected successfully.
[*] Retrying jennifer...
```

The username is retried instead of being classified as `INVALID`.

---

# SMTP Response Classification

| Response | Meaning                                | Result       |
| -------- | -------------------------------------- | ------------ |
| `250`    | Requested action completed             | `VALID`      |
| `251`    | User not local, forwarding possible    | `VALID`      |
| `252`    | Cannot verify user but accepts message | `VALID`      |
| `421`    | Temporary SMTP failure / throttling    | `RATE-LIMIT` |
| `550`    | User/mailbox unavailable               | `INVALID`    |
| `551`    | User not local                         | `INVALID`    |
| `553`    | Mailbox name not allowed               | `INVALID`    |

Example:

```text
[VALID]   root -> 252 2.0.0 root
[VALID]   robin -> 252 2.0.0 robin
[INVALID] T876 -> 550 5.1.1 <T876>: Recipient address rejected
```

---

# Output

Valid usernames are saved automatically to:

```text
valid_users.txt
```

Read the results:

```bash
cat valid_users.txt
```

Count valid users:

```bash
wc -l valid_users.txt
```

Use a custom output filename:

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY -o smtp_results.txt
```

Read it:

```bash
cat smtp_results.txt
```

---

# Example Full Commands

### Basic VRFY

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY
```

### VRFY + retry

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY --retry 5
```

### VRFY + timeout + delay

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY --timeout 15 --delay 1
```

### VRFY + custom output

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY -o results.txt
```

### EXPN

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M EXPN
```

### RCPT

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M RCPT -D inlanefreight.htb
```

### Complete configuration

```bash
python3 smtp_enum.py -t 10.129.169.159 -p 25 -w users.list -M VRFY --timeout 10 --delay 1 --retry 3 -o valid_users.txt
```

---

# Project Structure

```text
smtp-user-enumerator/
├── smtp_enum.py
├── users.list
├── valid_users.txt
└── README.md
```

---

# Troubleshooting

### SMTP port is closed

Check:

```bash
nmap -Pn -p25 -sV TARGET_IP
```

### SMTP capabilities

Check:

```bash
nmap -Pn -p25 --script smtp-commands TARGET_IP
```

### Increase timeout

```bash
python3 smtp_enum.py -t TARGET_IP -p 25 -w users.list -M VRFY --timeout 20
```

### Increase retries

```bash
python3 smtp_enum.py -t TARGET_IP -p 25 -w users.list -M VRFY --retry 5
```

### Add normal delay

```bash
python3 smtp_enum.py -t TARGET_IP -p 25 -w users.list -M VRFY --delay 2
```

---

# Security Notice

Use this tool only against SMTP servers that you are authorized to test.

Appropriate environments include:

* Penetration testing engagements
* CTF environments
* Hack The Box labs
* Security research environments
* Systems with explicit authorization

---

# Author

**Isriade Putra**

Security Practitioner / Security Researcher

Focus:

* Penetration Testing
* Web Application Security
* Network Security
* Mobile Application Security
* Security Research

<img width="1445" height="680" alt="image" src="https://github.com/user-attachments/assets/e83d5f2e-10de-44e4-9ca3-7d3e54840086" />
<img width="1764" height="763" alt="image" src="https://github.com/user-attachments/assets/f28b1da6-e9fd-4605-bdfb-6d78345591d8" />

