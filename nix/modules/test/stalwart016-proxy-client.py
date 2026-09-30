"""Real SMTP/IMAP and PROXY-v1 assertions for the isolated NixOS fixture."""

import argparse
import imaplib
import smtplib
import socket
import ssl


def forwarded():
    context = ssl.create_default_context(cafile="/run/mail-fixture.pem")
    for port in (25, 587):
        with smtplib.SMTP(timeout=10) as smtp:
            code, greeting = smtp.connect("mail.example.test", port)
            assert code == 220 and b"fixture-client=192.0.2.3" in greeting, greeting
            assert smtp.ehlo("client.example.test")[0] == 250
            assert smtp.has_extn("starttls")
            smtp._host = "mail.example.test"
            assert smtp.starttls(context=context)[0] == 220
            assert smtp.ehlo("client.example.test")[0] == 250
            if port == 25:
                assert smtp.mail("sender@external.test")[0] == 250
                code, response = smtp.rcpt("recipient@unrelated.test")
                assert code == 550 and b"relay" in response.lower(), (code, response)
    with imaplib.IMAP4_SSL("mail.example.test", 993, ssl_context=context, timeout=10) as imap:
        assert imap.capability()[0] == "OK"


def probe(mode, peer):
    header = b"PROXY TCP4 198.51.100.40 192.0.2.1 40000 25\r\n"
    with socket.create_connection(("192.0.2.1", 25), timeout=5) as connection:
        connection.settimeout(2)
        if mode == "missing":
            try:
                response = connection.recv(1024)
            except TimeoutError:
                return
            assert not response, response
        elif mode == "malformed":
            connection.sendall(b"PROXY TCP4 not-an-ip 192.0.2.1 40000 25\r\n")
            try:
                assert not connection.recv(1024)
            except ConnectionResetError:
                pass
        else:
            if mode == "trusted":
                connection.sendall(header)
            with connection.makefile("rb") as reader:
                greeting = reader.readline()
                expected = "198.51.100.40" if mode == "trusted" else peer
                assert greeting.startswith(b"220 "), greeting
                assert f"fixture-client={expected}".encode() in greeting, greeting
                if mode == "untrusted":
                    connection.sendall(header)
                    response = reader.readline()
                    assert response.startswith(b"5"), response


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["forwarded", "trusted", "missing", "malformed", "untrusted"])
    parser.add_argument("--peer", default="192.0.2.3")
    args = parser.parse_args()
    if args.mode == "forwarded":
        forwarded()
    else:
        probe(args.mode, args.peer)
