#!/usr/bin/env python3

import socket
import argparse
import time


def recv_smtp_response(sock):
    """
    Read an SMTP response, including multiline responses.
    """
    data = b""

    try:
        while True:
            chunk = sock.recv(4096)

            if not chunk:
                break

            data += chunk

            lines = data.decode(errors="ignore").splitlines()

            if not lines:
                continue

            last = lines[-1]

            # SMTP multiline response:
            # 250-...
            # 250 ...
            if len(last) >= 4 and last[:3].isdigit():
                if last[3] == " ":
                    break

            # Single-line response
            if len(last) >= 4 and last[:3].isdigit():
                break

    except socket.timeout:
        pass

    return data.decode(errors="ignore").strip()


def send_command(sock, command):
    try:
        sock.sendall((command + "\r\n").encode())
        return recv_smtp_response(sock)
    except socket.timeout:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


def smtp_enum(target, port, wordlist, method, domain, timeout):

    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        users = [x.strip() for x in f if x.strip()]

    print(f"[*] Target   : {target}:{port}")
    print(f"[*] Method   : {method}")
    print(f"[*] Wordlist : {wordlist}")
    print(f"[*] Users    : {len(users)}")
    print(f"[*] Timeout  : {timeout}s")
    print()

    try:
        sock = socket.create_connection(
            (target, port),
            timeout=timeout
        )

        sock.settimeout(timeout)

    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return

    # SMTP banner
    banner = recv_smtp_response(sock)

    if not banner:
        print("[!] No SMTP banner received.")
        print("[!] Try increasing --timeout.")
        sock.close()
        return

    print(f"[+] Banner:")
    print(banner)
    print()

    # EHLO
    response = send_command(
        sock,
        "EHLO inlanefreight.htb"
    )

    if response.startswith("[TIMEOUT]"):
        print("[!] EHLO response timeout.")
        sock.close()
        return

    print("[+] EHLO response:")
    print(response)
    print()

    # Enumeration
    for user in users:

        if method == "VRFY":

            response = send_command(
                sock,
                f"VRFY {user}"
            )

        elif method == "EXPN":

            response = send_command(
                sock,
                f"EXPN {user}"
            )

        elif method == "RCPT":

            response = send_command(
                sock,
                f"MAIL FROM:<test@{domain}>"
            )

            if response.startswith("[" ):
                print(f"[!] {user}: {response}")
                continue

            response = send_command(
                sock,
                f"RCPT TO:<{user}@{domain}>"
            )

        else:
            print(f"[!] Unsupported method: {method}")
            break

        # Extract SMTP response code
        code = response[:3]

        if code in ("250", "251", "252"):

            print(
                f"[VALID]   {user:<25} -> {response}"
            )

        elif code.startswith("5"):

            print(
                f"[INVALID] {user:<25} -> {response}"
            )

        elif code.startswith("4"):

            print(
                f"[TEMP]    {user:<25} -> {response}"
            )

        elif response.startswith("[TIMEOUT]"):

            print(
                f"[TIMEOUT] {user:<25}"
            )

        else:

            print(
                f"[?]       {user:<25} -> {response}"
            )

        # Small delay to avoid hammering the SMTP service
        time.sleep(0.05)

    try:
        send_command(sock, "QUIT")
        sock.close()
    except:
        pass


def main():

    parser = argparse.ArgumentParser(
        description="SMTP Username Enumeration"
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP or hostname"
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=25,
        help="SMTP port (default: 25)"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Username wordlist"
    )

    parser.add_argument(
        "-M",
        "--method",
        choices=["VRFY", "EXPN", "RCPT"],
        default="VRFY",
        help="Enumeration method"
    )

    parser.add_argument(
        "-D",
        "--domain",
        default="inlanefreight.htb",
        help="SMTP domain for RCPT"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Socket timeout in seconds"
    )

    args = parser.parse_args()

    smtp_enum(
        args.target,
        args.port,
        args.wordlist,
        args.method,
        args.domain,
        args.timeout
    )


if __name__ == "__main__":
    main()
