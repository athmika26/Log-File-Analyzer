import re
import csv
from collections import defaultdict
import os

def parse_log_file(log_file):
    # Checking if the log file exists.
    if not os.path.exists(log_file):
        raise FileNotFoundError(f"Log file '{log_file}' not found. Please check the path!")
    # Reading the file line by line.
    with open(log_file, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_count = defaultdict(int)
    for log in logs:
        # Extracting the IP address using regex
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip_count[match.group(1)] += 1
    # Sorting the IPs by request count in descending order
    return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

def find_most_accessed_endpoint(logs):
    endpoint_count = defaultdict(int) # Dictionary to store access counts for each endpoint
    for log in logs:
        # Extract the endpoint using regex
        match = re.search(r'\"[A-Z]+\s([^\s]+)\sHTTP', log)
        if match:
            endpoint_count[match.group(1)] += 1 # Increment the count for the matched endpoint
    # Find the endpoint with the maximum access count
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1], default=(None, 0))
    return most_accessed

def detect_suspicious_activity(logs, threshold):
    failed_logins = defaultdict(int) # Dictionary to store failed login counts per IP
    for log in logs:
        # Look for indicators of failed logins in the log line
        if '401' in log or 'Invalid credentials' in log:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                failed_logins[match.group(1)] += 1 # Increment the count for the matched IP
    # Return IPs that exceed the defined threshold
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def save_results_to_csv(requests, most_accessed, suspicious_activity, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in requests:
            writer.writerow([ip, count])
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        if most_accessed[0]:
            writer.writerow([most_accessed[0], most_accessed[1]])
        else:
            writer.writerow(["No data", "0"])
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    # User input for configurations
    log_file = input("Enter the path to the log file (default: 'sample.log'): ") or 'sample.log'
    output_csv = input("Enter the path for the output CSV file (default: 'log_analysis_results.csv'): ") or 'log_analysis_results.csv'
    try:
        failed_login_threshold = int(input("Enter the threshold for failed login attempts (default: 5): ") or 5)
    except ValueError:
        print("Invalid input for threshold. Using default value: 5")
        failed_login_threshold = 5
    
    try:
        logs = parse_log_file(log_file)
    except FileNotFoundError as e:
        print(e)
        return
    
    # 1. Count requests per IP
    requests = count_requests_per_ip(logs)
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count'}")
    for ip, count in requests:
        print(f"{ip:<20}{count}")
    
    # 2. Most accessed endpoint
    most_accessed = find_most_accessed_endpoint(logs)
    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed[0]:
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("No endpoints found.")
    
    # 3: Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(logs, failed_login_threshold)
    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print(f"{'IP Address':<20}{'Failed Login Attempts'}")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_results_to_csv(requests, most_accessed, suspicious_activity, output_csv)
    print(f"\nResults saved to {output_csv}")

if __name__ == "__main__":
    main()
