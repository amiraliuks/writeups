# crypto/bit-leak
 
| Field    | Details                                                                                      |
|----------|----------------------------------------------------------------------------------------------|
| **Name** | bit-leak                                                                                     |
| **Category** | Crypto                                                                                   |
| **Author** | andrew                                                                                     |
| **Points** | 211                                                                                        |
| **Description** | our security monitor only ever tips us off about the parity of RSA decryptions. turns out "even or odd" isn't much of a secret. can you recover the message one bit at a time? |

---
 
## Overview
 
The server generates an RSA keypair, encrypts a flag, and hands you the public key `(n, e)` and ciphertext `c`. The only operation available is submitting a ciphertext and getting back the **least significant bit** (LSB) of its decryption. You have a budget of 2100 queries.
 
One bit per query, 2100 query budget — more than enough to fully recover the plaintext.
 
---
 
## The Attack — RSA Parity Oracle
 
RSA is multiplicatively homomorphic: you can transform ciphertexts in predictable ways without the private key. Specifically, if you compute:
 
```
c' = c * 2^e mod n
```
 
then decrypting `c'` gives:
 
```
(c * 2^e)^d mod n = c^d * 2 mod n = 2m mod n
```
 
The modulus `n` is odd (product of two odd primes), so:
 
- If `2m < n` → no wrap → result is even → LSB = 0 → `m ∈ [0, n/2)`
- If `2m ≥ n` → wraps once → result is odd → LSB = 1 → `m ∈ [n/2, n)`
You just cut the plaintext search space in half with one query. Repeat with `4m`, `8m`, `16m`, ... and you're doing binary search on the plaintext. After `log2(n)` iterations — around 256 for a 256-bit modulus — the interval collapses to a single value.
 
---
 
## Solve Script
 
```python
#!/usr/bin/env python3
import argparse
import re
import socket
import sys
from fractions import Fraction
 
class Remote:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""
 
    def recv_until(self, marker):
        while marker not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"connection closed while waiting for {marker!r}")
            self.buffer += chunk
        end = self.buffer.index(marker) + len(marker)
        data = self.buffer[:end]
        self.buffer = self.buffer[end:]
        return data
 
    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")
 
def query_parity(remote, ciphertext):
    remote.recv_until(b"> ")
    remote.sendline("1")
    remote.recv_until(b"ciphertext = ")
    remote.sendline(str(ciphertext))
    response = remote.recv_until(b"lsb = ")
    response += remote.recv_until(b"\n")
    match = re.search(rb"lsb = ([01])", response)
    if not match:
        raise ValueError(f"could not parse oracle response: {response!r}")
    return int(match.group(1))
 
def int_to_bytes(value):
    return value.to_bytes((value.bit_length() + 7) // 8, "big")
 
def recover_plaintext(remote, n, e, ciphertext):
    lower = Fraction(0)
    upper = Fraction(n)
    multiplier = pow(2, e, n)
    probe = ciphertext
 
    for i in range(n.bit_length() + 8):
        probe = (probe * multiplier) % n
        bit = query_parity(remote, probe)
        midpoint = (lower + upper) / 2
        if bit == 0:
            upper = midpoint
        else:
            lower = midpoint
 
        if (i + 1) % 64 == 0:
            print(f"[+] {i + 1} oracle queries", file=sys.stderr, flush=True)
 
        candidate = int(upper)
        decoded = int_to_bytes(candidate)
        if i > 32 and decoded.startswith(b"tjctf{") and decoded.endswith(b"}"):
            return decoded
 
    for candidate in range(int(lower) - 2, int(upper) + 3):
        if candidate >= 0:
            decoded = int_to_bytes(candidate)
            if decoded.startswith(b"tjctf{") and decoded.endswith(b"}"):
                return decoded
 
    return int_to_bytes(int(upper))
 
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="tjc.tf")
    parser.add_argument("port", nargs="?", type=int, default=31001)
    args = parser.parse_args()
 
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(None)
        print(f"[+] connected to {args.host}:{args.port}", file=sys.stderr, flush=True)
        remote = Remote(sock)
        banner = remote.recv_until(b"parity queries.")
        print("[+] received RSA parameters", file=sys.stderr, flush=True)
 
        n = int(re.search(rb"n = ([0-9]+)", banner).group(1))
        e = int(re.search(rb"e = ([0-9]+)", banner).group(1))
        ciphertext = int(re.search(rb"ciphertext = ([0-9]+)", banner).group(1))
 
        plaintext = recover_plaintext(remote, n, e, ciphertext)
        print(plaintext.decode(errors="replace"))
 
if __name__ == "__main__":
    main()
```
 
The interval bounds use `fractions.Fraction` instead of floats — over 500+ iterations, float drift would corrupt the result, so exact rationals are the right call. `recv_until` handles buffered socket reads to stay in sync with the server's menu prompts without needing pwntools. The early-exit check on `startswith(b"tjctf{")` means it stops as soon as the interval is narrow enough to decode the flag, usually before hitting the full `n.bit_length() + 8` iteration cap.
 
---
 
## Output
 
```
$ python3 solve.py
[+] connected to tjc.tf:31001
[+] received RSA parameters
[+] 64 oracle queries
[+] 128 oracle queries
[+] 192 oracle queries
[+] 256 oracle queries
[+] 320 oracle queries
[+] 384 oracle queries
[+] 448 oracle queries
tjctf{parity_isnt_privacy}
```
 
~512 queries used, well within the 2100 limit.
 
---
 
## Flag
 
```
tjctf{parity_isnt_privacy}
```