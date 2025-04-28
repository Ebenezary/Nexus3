import os
import sys
from datetime import datetime
from web3 import Account


number_of_keys = 5  # Number of keys to generate

def log(msg):
    now = datetime.now().isoformat(" ").split(".")[0]
    print(f"[{now}] {msg}")

def generate_keys(number_of_keys):
    try:
        file_path = "privatekeys.txt"

        if os.path.exists(file_path):
            with open(file_path, "rb+") as f:
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                if file_size > 0:
                    f.seek(-1, os.SEEK_END)
                    last_char = f.read(1)
                    if last_char != b'\n':
                        f.write(b'\n')


        with open(file_path, "a", encoding="utf-8") as file:
            for i in range(number_of_keys):
                wallet = Account.create()
                private_key = f"0x{wallet.key.hex()}"
                file.write(f"{private_key}\n")
                log(f"Key Generated {i + 1}/{number_of_keys}: Address: {wallet.address}")

        log(f"Successfully wrote {number_of_keys} private keys to {file_path}")
    except Exception as e:
        log(f"An error occurred while generating keys: {e}")

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(">\n> Ethereum Private Key Generator\n>")
    print()

    try:
        if number_of_keys <= 0:
            log("Number of keys must be greater than 0.")
            return

        generate_keys(number_of_keys)
    except ValueError:
        log("Invalid input. Please enter a positive integer.")
    except KeyboardInterrupt:
        log("Process interrupted by the user.")
        sys.exit()


if __name__ == "__main__":
    main()