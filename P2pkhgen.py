import os
import time
import threading
import hashlib
import base58
from ecdsa import SECP256k1, SigningKey
from datetime import datetime

# === GLOBAL CONFIG ===
SAVE_EVERY = 10000
RESUME_FILE = "resume_count.txt"
MATCH_FILE = "match_found.txt"

# === RUNTIME GLOBALS ===
counter = 0
start_time = time.time()
counter_lock = threading.Lock()
TARGET_ADDRESS = ""
THREADS = 10

def save_resume(count):
    with open(RESUME_FILE, "w") as f:
        f.write(str(count))

def load_resume():
    if os.path.exists(RESUME_FILE):
        with open(RESUME_FILE, "r") as f:
            return int(f.read())
    return 0

def private_key_to_wif(priv_key_bytes):
    prefix = b'\x80'
    suffix = b'\x01'
    payload = prefix + priv_key_bytes + suffix
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def public_key_to_p2pkh(pubkey_bytes):
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    prefixed = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
    return base58.b58encode(prefixed + checksum).decode()

def generate_and_check():
    global counter
    while True:
        priv_key = SigningKey.generate(curve=SECP256k1)
        pub_key = priv_key.get_verifying_key()
        pub_key_bytes = b'\x02' + pub_key.to_string()[:32] if pub_key.to_string()[63] % 2 == 0 else b'\x03' + pub_key.to_string()[:32]
        address = public_key_to_p2pkh(pub_key_bytes)

        with counter_lock:
            counter += 1
            if counter % SAVE_EVERY == 0:
                save_resume(counter)

        if address == TARGET_ADDRESS:
            wif = private_key_to_wif(priv_key.to_string())
            with open(MATCH_FILE, "a") as f:
                f.write(f"Match found at {datetime.utcnow()}:\nAddress: {address}\nWIF: {wif}\n\n")
            print("🎯 MATCH FOUND!")
            os._exit(0)

def print_stats():
    global counter
    while True:
        time.sleep(5)
        elapsed = time.time() - start_time
        with counter_lock:
            rate = counter / elapsed
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Checked: {counter:,} | Rate: {rate:.2f}/s | Elapsed: {int(elapsed)}s")

# === MAIN ===
if __name__ == "__main__":
    print("⚡ Bitcoin P2PKH Target Finder")
    TARGET_ADDRESS = input("🎯 Enter target P2PKH address (starts with 1): ").strip()
    threads_input = input("🔁 Enter number of threads [default 10]: ").strip()
    THREADS = int(threads_input) if threads_input.isdigit() and int(threads_input) > 0 else 10

    counter = load_resume()
    print(f"🔄 Resuming from count: {counter}")
    print(f"🧵 Using {THREADS} threads")

    threading.Thread(target=print_stats, daemon=True).start()

    for i in range(THREADS):
        threading.Thread(target=generate_and_check, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Exiting. Progress saved.")
