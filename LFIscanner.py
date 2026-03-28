#!/usr/bin/env python3
import requests
import sys

TIMEOUT = 5
HEADERS = {
    "User-Agent": "LFI-Scanner / Authorized Testing"
}

LFI_SIGS = [
    "root:x:0:0",
    "/bin/bash",
    "daemon:x",
    "www-data"
]

def load_payloads(path):
    with open(path, "r", errors="ignore") as f:
        return [x.strip() for x in f if x.strip()]

def is_lfi(text):
    for sig in LFI_SIGS:
        if sig in text:
            return sig
    return None

def scan(url, payloads):
    print(f"[+] Target: {url}")
    print(f"[+] Payloads: {len(payloads)}")

    if "=" not in url:
        print("[!] URL must end with parameter (e.g ?page=)")
        sys.exit(1)

    findings = []

    for payload in payloads:
        test_url = url + payload

        try:
            r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT)
            sig = is_lfi(r.text)

            print(f"[-] Testing: {payload}")

            if sig:
                print("\n" + "=" * 60)
                print("[!!!] LFI CONFIRMED (LINUX)")
                print(f"[+] Payload  : {payload}")
                print(f"[+] Evidence : {sig}")
                print(f"[+] URL      : {test_url}")
                print("=" * 60)

                findings.append((payload, sig, test_url))

        except:
            pass


    if findings:
        print("\n🔥 SUMMARY — LFI FOUND 🔥")
        for f in findings:
            print(f"[+] {f[0]}  --> {f[1]}")
    else:
        print("\n[✓] No LFI detected.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 LFI_SCANNER_FINAL.py <URL_WITH_PARAM=> <payloads.txt>")
        sys.exit(1)

    scan(sys.argv[1], load_payloads(sys.argv[2]))
