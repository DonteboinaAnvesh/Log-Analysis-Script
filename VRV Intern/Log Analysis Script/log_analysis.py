import re
import csv
from collections import defaultdict

LOG_FILE_PATH = "sample.log"
CSV_FILE_PATH = "log_analysis_results.csv"

FAILED_LOGIN_THRESHOLD = 10

ip_request_counts = defaultdict(int)
endpoint_access_counts = defaultdict(int)
failed_login_attempts = defaultdict(int)

log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) .*? "(?P<method>GET|POST) (?P<endpoint>.*?) HTTP/1\.\d" (?P<status>\d+)'
)

try:
    with open(LOG_FILE_PATH, 'r') as log_file:
        for line in log_file:
            match = log_pattern.match(line)
            if match:
                ip = match.group("ip")
                endpoint = match.group("endpoint")
                status = match.group("status")

                ip_request_counts[ip] += 1

                endpoint_access_counts[endpoint] += 1

                if status == "401":
                    failed_login_attempts[ip] += 1

except FileNotFoundError:
    print(f"Error: File '{LOG_FILE_PATH}' not found.")
    exit(1)
most_accessed_endpoint = max(
    endpoint_access_counts.items(), key=lambda x: x[1], default=("None", 0)
)

suspicious_ips = {
    ip: count
    for ip, count in failed_login_attempts.items()
    if count > FAILED_LOGIN_THRESHOLD
}

print("IP Address           Request Count")
for ip, count in sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip:<20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

print("\nSuspicious Activity Detected:")
print("IP Address           Failed Login Attempts")
if suspicious_ips:
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
else:
    print("No suspicious activity detected.")

with open(CSV_FILE_PATH, mode="w", newline="") as csv_file:
    writer = csv.writer(csv_file)

    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(
        sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)
    )

    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow(most_accessed_endpoint)

    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    writer.writerows(suspicious_ips.items())

print(f"\nResults saved to {CSV_FILE_PATH}.")
