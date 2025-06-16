import os
import time
import subprocess
import threading
from rich import print
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === CONFIG ===
PYTHON_EXECUTABLE = "python"
MAL_PROTOCOL_PATH = os.path.join(os.path.dirname(__file__), "malprotocol.py")
RISK_THRESHOLD = 30
MAX_FILE_SIZE_MB = 100

# === Risk Parser ===
def extract_risk(output: str) -> int:
    for line in output.splitlines():
        if "RISK_SCORE:" in line:
            try:
                return int(line.strip().split("RISK_SCORE:")[1])
            except:
                pass
    return 0

# === Scan File ===
def scan_file(file_path):
    try:
        if not os.path.isfile(file_path):
            return
        if os.path.getsize(file_path) > MAX_FILE_SIZE_MB * 1024 * 1024:
            return
        if file_path.lower().endswith(".tmp"):
            return

        time.sleep(2)  # wait to ensure file is fully written
        print(f"[cyan]🧪 Scanning new file:[/] {file_path}")

        result = subprocess.run(
            [PYTHON_EXECUTABLE, MAL_PROTOCOL_PATH, file_path, "--no-vt"],
            capture_output=True, text=True, timeout=120
        )

        risk = extract_risk(result.stdout)
        print(f"[yellow]→ Risk Score:[/] {risk}%")

        if risk >= RISK_THRESHOLD:
            print(f"[red]⚠️ Deleting file (Risk ≥ {RISK_THRESHOLD}%):[/] {file_path}")
            os.remove(file_path)

    except Exception as e:
        print(f"[red]❌ Error scanning file {file_path}: {e}[/red]")

# === Watchdog Handler ===
class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            threading.Thread(target=scan_file, args=(event.src_path,), daemon=True).start()

# === Watch All Local Drives ===
def get_all_system_paths():
    paths = []
    for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        path = f"{drive}:\\"
        if os.path.exists(path):
            paths.append(path)
    return paths

# === Main Runner ===
if __name__ == "__main__":
    print("[bold green]🛡️ Mal-Protocol Global Monitor Running[/bold green]")
    print(f"📡 Monitoring all system drives for new files...")
    print(f"⚠️ Files with Risk ≥ {RISK_THRESHOLD}% will be deleted.\n")

    observer = Observer()
    handler = FileHandler()

    for path in get_all_system_paths():
        try:
            observer.schedule(handler, path, recursive=True)
        except Exception as e:
            print(f"[red]⚠️ Could not monitor {path}: {e}[/red]")

    observer.start()
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
