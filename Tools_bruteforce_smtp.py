#!/usr/bin/env python3

import argparse
import re
import socket
import sys
import time


# ============================================================
# SMTP RESPONSE
# ============================================================

def recv_smtp_response(sock, timeout):
    """
    Receive a complete SMTP response.

    Supports both:
        250 OK

    and multiline:
        250-mail1
        250-PIPELINING
        250 STARTTLS
    """

    sock.settimeout(timeout)

    data = b""

    while True:
        chunk = sock.recv(4096)

        if not chunk:
            raise ConnectionResetError(
                "SMTP server closed the connection"
            )

        data += chunk

        text = data.decode(errors="replace")
        lines = text.splitlines()

        if not lines:
            continue

        # SMTP multiline response ends with:
        # 250 <message>
        #
        # while intermediate lines use:
        # 250-<message>
        if re.search(r"^\d{3} ", lines[-1]):
            break

    return text.strip()


def get_smtp_code(response):
    """
    Extract the first SMTP status code.

    Example:
        252 2.0.0 robin
        -> 252
    """

    if not response:
        return None

    match = re.search(r"^(\d{3})", response)

    if match:
        return int(match.group(1))

    return None


# ============================================================
# RATE-LIMIT DETECTION
# ============================================================

def detect_rate_limit(response):
    """
    Detect whether the SMTP server is asking us to slow down.

    Returns:
        (True, delay_seconds)
        (False, 0)
    """

    if not response:
        return False, 0

    response_lower = response.lower()

    code = get_smtp_code(response)

    # --------------------------------------------------------
    # Explicit SMTP temporary failure
    # --------------------------------------------------------

    if code == 421:
        delay = extract_delay(response)

        if delay is None:
            delay = 3

        return True, delay

    # --------------------------------------------------------
    # Common rate-limit phrases
    # --------------------------------------------------------

    keywords = [
        "too many errors",
        "too many requests",
        "too many connections",
        "rate limit",
        "rate-limit",
        "rate exceeded",
        "temporarily blocked",
        "temporarily unavailable",
        "try again later",
        "slow down",
        "throttl",
    ]

    for keyword in keywords:

        if keyword in response_lower:

            delay = extract_delay(response)

            if delay is None:
                delay = 3

            return True, delay

    return False, 0


def extract_delay(response):
    """
    Try to extract a delay/retry time from the SMTP response.

    Examples that may be detected:

        retry after 10 seconds
        wait 5 seconds
        retry in 30 seconds
        30 seconds
        10 sec

    Returns:
        integer seconds or None
    """

    patterns = [

        r"retry[- ]after\s+(\d+)\s*seconds?",
        r"retry[- ]after\s+(\d+)\s*secs?",
        r"retry\s+in\s+(\d+)\s*seconds?",
        r"retry\s+in\s+(\d+)\s*secs?",
        r"wait\s+(\d+)\s*seconds?",
        r"wait\s+(\d+)\s*secs?",
        r"(\d+)\s*seconds?",
        r"(\d+)\s*secs?",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            response,
            re.IGNORECASE
        )

        if match:

            try:
                value = int(match.group(1))

                # Prevent an unreasonable server response
                # from creating an extremely long sleep.
                return min(value, 300)

            except ValueError:
                pass

    return None


# ============================================================
# SMTP CONNECTION
# ============================================================

def connect_smtp(target, port, timeout):
    """
    Connect to SMTP server and perform EHLO.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    sock.connect(
        (target, port)
    )

    # --------------------------------------------------------
    # SMTP banner
    # --------------------------------------------------------

    banner = recv_smtp_response(
        sock,
        timeout
    )

    # --------------------------------------------------------
    # EHLO
    # --------------------------------------------------------

    sock.sendall(
        b"EHLO inlanefreight.htb\r\n"
    )

    ehlo = recv_smtp_response(
        sock,
        timeout
    )

    return sock, banner, ehlo


def close_smtp(sock):
    """
    Safely close SMTP connection.
    """

    if sock is None:
        return

    try:

        sock.sendall(
            b"QUIT\r\n"
        )

        sock.settimeout(2)

        try:
            recv_smtp_response(sock, 2)
        except Exception:
            pass

    except Exception:
        pass

    try:
        sock.close()
    except Exception:
        pass


# ============================================================
# SMTP METHODS
# ============================================================

def smtp_vrfy(sock, username, timeout):

    command = f"VRFY {username}\r\n"

    sock.sendall(
        command.encode()
    )

    return recv_smtp_response(
        sock,
        timeout
    )


def smtp_expn(sock, username, timeout):

    command = f"EXPN {username}\r\n"

    sock.sendall(
        command.encode()
    )

    return recv_smtp_response(
        sock,
        timeout
    )


def smtp_rcpt(sock, username, domain, timeout):

    sender = "test@inlanefreight.htb"
    recipient = f"{username}@{domain}"

    # --------------------------------------------------------
    # MAIL FROM
    # --------------------------------------------------------

    sock.sendall(
        f"MAIL FROM:<{sender}>\r\n".encode()
    )

    mail_response = recv_smtp_response(
        sock,
        timeout
    )

    mail_code = get_smtp_code(
        mail_response
    )

    if mail_code == 421:
        return mail_response

    # --------------------------------------------------------
    # RCPT TO
    # --------------------------------------------------------

    sock.sendall(
        f"RCPT TO:<{recipient}>\r\n".encode()
    )

    rcpt_response = recv_smtp_response(
        sock,
        timeout
    )

    # --------------------------------------------------------
    # Reset transaction
    # --------------------------------------------------------

    try:

        sock.sendall(
            b"RSET\r\n"
        )

        recv_smtp_response(
            sock,
            timeout
        )

    except Exception:
        pass

    return rcpt_response


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_response(response):
    """
    Classify SMTP response.

    Returns:
        VALID
        INVALID
        RATE_LIMIT
        UNKNOWN
    """

    code = get_smtp_code(
        response
    )

    # --------------------------------------------------------
    # Rate limit
    # --------------------------------------------------------

    rate_limited, _ = detect_rate_limit(
        response
    )

    if rate_limited:
        return "RATE_LIMIT"

    # --------------------------------------------------------
    # Valid recipient
    # --------------------------------------------------------

    if code in (
        250,
        251,
        252
    ):
        return "VALID"

    # --------------------------------------------------------
    # Invalid recipient
    # --------------------------------------------------------

    if code in (
        550,
        551,
        553
    ):
        return "INVALID"

    return "UNKNOWN"


# ============================================================
# ARGUMENTS
# ============================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "SMTP Username Enumeration with "
            "adaptive rate-limit handling"
        )
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="SMTP target IP/hostname"
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
        choices=[
            "VRFY",
            "EXPN",
            "RCPT"
        ],
        default="VRFY",
        help="Enumeration method"
    )

    parser.add_argument(
        "-D",
        "--domain",
        default="inlanefreight.htb",
        help="Domain for RCPT"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Socket timeout (default: 10)"
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        help=(
            "Normal delay between requests "
            "(default: 0)"
        )
    )

    parser.add_argument(
        "--retry",
        type=int,
        default=3,
        help=(
            "Maximum retries after connection/rate-limit "
            "(default: 3)"
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        default="valid_users.txt",
        help=(
            "Output file for valid users "
            "(default: valid_users.txt)"
        )
    )

    return parser.parse_args()


# ============================================================
# RECONNECT
# ============================================================

def reconnect(target, port, timeout, delay):

    print(
        f"[*] Waiting {delay} seconds before reconnect..."
    )

    time.sleep(delay)

    return connect_smtp(
        target,
        port,
        timeout
    )


# ============================================================
# MAIN
# ============================================================

def main():

    args = parse_args()

    # --------------------------------------------------------
    # Load wordlist
    # --------------------------------------------------------

    try:

        with open(
            args.wordlist,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            users = []

            for line in f:

                username = line.strip()

                if (
                    username
                    and username not in users
                ):
                    users.append(username)

    except FileNotFoundError:

        print(
            f"[-] Wordlist not found: "
            f"{args.wordlist}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    print(
        f"[*] Target   : "
        f"{args.target}:{args.port}"
    )

    print(
        f"[*] Method   : "
        f"{args.method}"
    )

    print(
        f"[*] Wordlist : "
        f"{args.wordlist}"
    )

    print(
        f"[*] Users    : "
        f"{len(users)}"
    )

    print(
        f"[*] Timeout  : "
        f"{args.timeout}s"
    )

    print(
        f"[*] Retry    : "
        f"{args.retry}"
    )

    print()

    # --------------------------------------------------------
    # Initial connection
    # --------------------------------------------------------

    sock = None

    try:

        print(
            "[*] Connecting..."
        )

        sock, banner, ehlo = connect_smtp(
            args.target,
            args.port,
            args.timeout
        )

    except Exception as e:

        print(
            f"[-] Connection failed: {e}"
        )

        sys.exit(1)

    print(
        "[+] Banner:"
    )

    print(
        banner
    )

    print()

    print(
        "[+] EHLO response:"
    )

    print(
        ehlo
    )

    print()

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    valid_users = []

    # ========================================================
    # ENUMERATION LOOP
    # ========================================================

    for username in users:

        retry_count = 0

        while True:

            try:

                # --------------------------------------------
                # Recover if the connection was lost
                # (reconnect failure paths leave sock = None)
                # --------------------------------------------

                if sock is None:

                    sock, banner, ehlo = connect_smtp(
                        args.target,
                        args.port,
                        args.timeout
                    )

                    print(
                        "[+] Reconnected successfully."
                    )

                # --------------------------------------------
                # Execute method
                # --------------------------------------------

                if args.method == "VRFY":

                    response = smtp_vrfy(
                        sock,
                        username,
                        args.timeout
                    )

                elif args.method == "EXPN":

                    response = smtp_expn(
                        sock,
                        username,
                        args.timeout
                    )

                elif args.method == "RCPT":

                    response = smtp_rcpt(
                        sock,
                        username,
                        args.domain,
                        args.timeout
                    )

                else:

                    response = ""

                # --------------------------------------------
                # Detect rate limit
                # --------------------------------------------

                is_rate_limited, server_delay = (
                    detect_rate_limit(
                        response
                    )
                )

                if is_rate_limited:

                    retry_count += 1

                    print()

                    print(
                        f"[RATE-LIMIT] "
                        f"{username:<25} -> "
                        f"{response}"
                    )

                    if retry_count > args.retry:

                        print(
                            f"[RETRY]   "
                            f"{username:<25} -> "
                            f"maximum retries reached"
                        )

                        break

                    # ----------------------------------------
                    # Close old connection
                    # ----------------------------------------

                    close_smtp(
                        sock
                    )

                    sock = None

                    print(
                        f"[*] Server requested/indicated "
                        f"slowdown."
                    )

                    try:

                        sock, banner, ehlo = reconnect(
                            args.target,
                            args.port,
                            args.timeout,
                            server_delay
                        )

                        print(
                            "[+] Reconnected successfully."
                        )

                        print(
                            f"[*] Retrying "
                            f"{username}..."
                        )

                        continue

                    except Exception as e:

                        print(
                            f"[-] Reconnect failed: "
                            f"{e}"
                        )

                        time.sleep(
                            server_delay
                        )

                        continue

                # --------------------------------------------
                # Normal classification
                # --------------------------------------------

                result = classify_response(
                    response
                )

                if result == "VALID":

                    print(
                        f"[VALID]   "
                        f"{username:<25} -> "
                        f"{response}"
                    )

                    if username not in valid_users:

                        valid_users.append(
                            username
                        )

                elif result == "INVALID":

                    print(
                        f"[INVALID] "
                        f"{username:<25} -> "
                        f"{response}"
                    )

                else:

                    print(
                        f"[?]       "
                        f"{username:<25} -> "
                        f"{response}"
                    )

                break

            # =================================================
            # CONNECTION ERRORS
            # =================================================

            except (
                BrokenPipeError,
                ConnectionResetError,
                ConnectionAbortedError,
                ConnectionRefusedError,
                TimeoutError,
                socket.timeout,
                OSError
            ) as e:

                retry_count += 1

                print()

                print(
                    f"[CONNECTION] "
                    f"{username:<25} -> "
                    f"{type(e).__name__}: {e}"
                )

                close_smtp(
                    sock
                )

                sock = None

                if retry_count > args.retry:

                    print(
                        f"[RETRY]   "
                        f"{username:<25} -> "
                        f"maximum retries reached"
                    )

                    break

                # --------------------------------------------
                # Adaptive reconnect
                # --------------------------------------------

                # Start with a small delay.
                # Increase it after repeated failures.

                reconnect_delay = min(
                    2 ** retry_count,
                    30
                )

                print(
                    f"[*] Waiting "
                    f"{reconnect_delay}s..."
                )

                time.sleep(
                    reconnect_delay
                )

                try:

                    sock, banner, ehlo = (
                        connect_smtp(
                            args.target,
                            args.port,
                            args.timeout
                        )
                    )

                    print(
                        "[+] Reconnected successfully."
                    )

                    print(
                        f"[*] Retrying "
                        f"{username}..."
                    )

                except Exception as reconnect_error:

                    print(
                        f"[-] Reconnect failed: "
                        f"{reconnect_error}"
                    )

                    time.sleep(
                        reconnect_delay
                    )

        # ----------------------------------------------------
        # Normal optional delay
        # ----------------------------------------------------

        if args.delay > 0:

            time.sleep(
                args.delay
            )

    # ========================================================
    # CLOSE
    # ========================================================

    close_smtp(
        sock
    )

    # ========================================================
    # SAVE RESULTS
    # ========================================================

    try:

        with open(
            args.output,
            "w",
            encoding="utf-8"
        ) as f:

            for username in valid_users:

                f.write(
                    username + "\n"
                )

    except Exception as e:

        print(
            f"[-] Could not save output: {e}"
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()

    print(
        "=" * 60
    )

    print(
        "[+] Enumeration completed"
    )

    print(
        "=" * 60
    )

    print(
        f"[*] Valid users : "
        f"{len(valid_users)}"
    )

    print(
        f"[*] Output      : "
        f"{args.output}"
    )

    if valid_users:

        print()

        print(
            "[+] Valid usernames:"
        )

        for username in valid_users:

            print(
                f"    {username}"
            )


if __name__ == "__main__":
    main()

