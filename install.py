# Consult your village people if you still mess this up

import subprocess

try:
    subprocess.check_call(['python', '-m', 'pip', 'install', '-r', 'requirements.txt'])
    print("Requirements installed successfully.")
except subprocess.CalledProcessError as e:
    print(f"An error occurred while installing requirements: {e}")

