import re
from collections import Counter

# Configuration (on Debian/Ubuntu: /var/log/auth.log | on RHEL/CentOS: /var/log/secure)
AUTH_LOG_FILE = "/var/log/auth.log"
ALERT_THRESHOLD = 5

def analyze_ssh_logs(file_path):
    failures_by_ip = Counter()
    targeted_users = Counter()

    # Regex adapted to the standard sshd format:
    # Captures the user (optionally preceded by "invalid user ") and the IP after "from "
    ssh_pattern = re.compile(
        r"sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )

    try:
        # errors="ignore" prevents a crash if a corrupted binary character appears in the logs
        with open(file_path, "r", encoding="utf-8", errors="ignore") as log_file:
            for line in log_file:
                match = ssh_pattern.search(line)
                if match:
                    user = match.group(1)
                    ip = match.group(2)

                    failures_by_ip[ip] += 1
                    targeted_users[user] += 1

    except FileNotFoundError:
        print(f"[ERROR] The file '{file_path}' does not exist on this system.")
        return
    except PermissionError:
        print(f"[ERROR] Permission denied when reading '{file_path}'.")
        print("-> Run the script with administrator privileges: sudo python3 ssh_log_analyzer.py")
        return

    # --- DISPLAY REPORT ---
    print(f"=== SSH LOG ANALYSIS ({file_path}) ===\n")

    print("--- Suspicious IPs (Failed login attempts) ---")
    if not failures_by_ip:
        print("No failed SSH login attempts detected.")
    else:
        for ip, count in failures_by_ip.most_common():
            if count >= ALERT_THRESHOLD:
                print(f"[CRITICAL ALERT] {ip}: {count} failures")
            else:
                print(f"[INFO] {ip}: {count} failure(s)")

    print("\n--- Top 5 targeted accounts ---")
    for user, count in targeted_users.most_common(5):
        print(f"User '{user}': {count} attempt(s)")

if __name__ == "__main__":
    analyze_ssh_logs(AUTH_LOG_FILE)