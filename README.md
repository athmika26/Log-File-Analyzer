# Log File Analyzer

This Python program analyzes server log files to provide insights such as the number of requests per IP address, the most accessed endpoint, and suspicious activities based on failed login attempts. The results are saved in a CSV file.

---

## Features

1. **Requests Per IP Address**  
   Counts the number of requests made by each IP address and lists them in descending order of frequency.

2. **Most Accessed Endpoint**  
   Identifies the endpoint that was accessed the most from the logs.

3. **Suspicious Activity Detection**  
   Detects IP addresses with failed login attempts exceeding a user-defined threshold.

4. **CSV Output**  
   Saves the analysis results to a CSV file for easy access and sharing.

---

## Requirements

- Python 3.6 or later
- No additional libraries are required beyond the Python standard library.

---

## Configuration Options

The program allows the following configurations through user input:

1. **Log File Path**  
   Enter the path to the log file to analyze (default: `sample.log`).

2. **Output CSV Path**  
   Enter the path where the results will be saved (default: `log_analysis_results.csv`).

3. **Failed Login Threshold**  
   Enter the threshold for the number of failed login attempts to flag as suspicious activity (default: `5`).

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/log-file-analyzer.git
   cd log-file-analyzer
2. Ensure you have Python 3 installed:
   ```bash
   python --version
3. Place your log file in the project directory or specify its path when running the program.
4. Run the program using the following command:
   ```bash
   python log_analyzer.py

---

## Output

The program provides:
1. Console Output:
Requests per IP address
Most accessed endpoint
Suspicious activity detected
2. CSV File:
Results are saved in a CSV file at the specified path (default: log_analysis_results.csv).

---

## Example output

Here’s an example of how the program’s output would look based on the provided data with a threshold of 7:

Console Output
```bash
Requests per IP Address:
IP Address          Request Count
203.0.113.5         8
198.51.100.23       8
192.168.1.1         7
10.0.0.2            6
192.168.1.100       5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
IP Address          Failed Login Attempts
203.0.113.5         8
```
![image](https://github.com/user-attachments/assets/ef0bd19e-d60a-4ea5-8085-191baebf6517)
