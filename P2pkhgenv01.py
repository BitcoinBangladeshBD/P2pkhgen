import os
import time
import threading
import random
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import hashlib
import base58

# === CONFIG ===
RESUME_FILE = "resume.txt"
MNEMONIC_LANG = "english"
mnemo = Mnemonic(MNEMONIC_LANG)

counter = 0
found = 0
TARGET_ADDRESS = ""
THREADS = 10

lock = threading.Lock()


def sha256(data):
    return hashlib.sha256(data).digest()


def ripemd160(data):
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def generate_p2pkh(pubkey_bytes):
    pubkey_hash = ripemd160(sha256(pubkey_bytes))
    prefix = b'\x00'  # Mainnet P2PKH
    checksum = sha256(sha256(prefix + pubkey_hash))[:4]
    address_bytes = prefix + pubkey_hash + checksum
    return base58.b58encode(address_bytes).decode()


def generate_and_check():
    global counter, found
    while True:
        mnemonic = mnemo.generate(strength=128)
        seed = mnemo.to_seed(mnemonic, passphrase="")
        bip32_root_key_obj = BIP32Key.fromEntropy(seed)
        bip32_child_key_obj = bip32_root_key_obj.ChildKey(44 + BIP32Key.HARDEN).ChildKey(0 + BIP32Key.HARDEN).ChildKey(0 + BIP32Key.HARDEN).ChildKey(0).ChildKey(0)
        pubkey = bip32_child_key_obj.PublicKey()
        address = generate_p2pkh(pubkey)

        with lock:
            counter += 1
            if address == TARGET_ADDRESS:
                found += 1
                with open("found.txt", "a") as f:
                    f.write(f"FOUND! Mnemonic: {mnemonic}\nAddress: {address}\n\n")
                print(f"\n✅ FOUND MATCH!\nMnemonic: {mnemonic}\nAddress: {address}\n")
            if counter % 1000 == 0:
                with open(RESUME_FILE, "w") as f:
                    f.write(str(counter))


def print_stats():
    while True:
        with lock:
            print(f"[+] Checked: {counter:,} | Found: {found} | Threads: {THREADS}", end="\r")
        time.sleep(1)


def load_resume():
    if os.path.exists(RESUME_FILE):
        try:
            with open(RESUME_FILE, "r") as f:
                return int(f.read().strip())
        except:
            return 0
    return 0


# === MAIN ===
if __name__ == "__main__":
    print("⚡ Bitcoin P2PKH Target Finder")

    choice = input("📂 Choose input method:\n[1] Manual address input\n[2] Load from 'target.txt'\nEnter choice [1/2]: ").strip()

    if choice == '2':
        try:
            with open("target.txt", "r") as f:
                TARGET_ADDRESS = f.readline().strip()
                if not TARGET_ADDRESS or not TARGET_ADDRESS.startswith("1"):
                    raise ValueError("Invalid address in target.txt")
        except Exception as e:
            print(f"❌ Failed to read target.txt: {e}")
            exit(1)
    else:
        TARGET_ADDRESS = input("🎯 Enter target P2PKH address (starts with 1): ").strip()
        if not TARGET_ADDRESS.startswith("1") or len(TARGET_ADDRESS) < 26:
            print("❌ Invalid P2PKH address format.")
            exit(1)

    threads_input = input("🔁 Enter number of threads [default 10]: ").strip()
    THREADS = int(threads_input) if threads_input.isdigit() and int(threads_input) > 0 else 10

    counter = load_resume()
    print(f"🔄 Resuming from count: {counter}")
    print(f"🧵 Using {THREADS} threads")
    print(f"🎯 Target Address: {TARGET_ADDRESS}")

    threading.Thread(target=print_stats, daemon=True).start()

    for i in range(THREADS):
        threading.Thread(target=generate_and_check, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Exiting. Progress saved.")
