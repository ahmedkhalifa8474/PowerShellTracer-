
Python Script to Detect Remote Connections & PowerShell Executions Using Event IDs and IOCs

"Overview"

PowerShellTracer is a Python script designed to collect and analyze event logs from Windows systems. It focuses on PowerShell, security, Sysmon, and scheduled task logs to identify potential malicious activities. The script allows users to specify a time range (e.g., the last 6 hours) and outputs results in a CSV file named PowerShell.csv for easy analysis.

"Key Features"
1. PowerShell Event Log Collection
Captures PowerShell-related logs (e.g., Event IDs 4103, 4104, 4105, 4106).

2. Security Event Log Integration
Extracts security-related event logs, including:

4688: Process creation
4689: Process termination
4648: Account logon
3. Sysmon Event Monitoring
Monitors system activity using Sysmon Event IDs:

1: Process creation
3: Network connections
11: File creation time


4. Scheduled Task Event Analysis
Detects task creation or modifications using Event IDs 4697 and 4698.

5. Time-Based Filtering
Filters logs based on a specified time range (e.g., last 6 hours).

6. CSV Output
Outputs results in a structured CSV file (PowerShell.csv) with details like Event ID, timestamp, command, user, and process ID.

7. Comprehensive IOC Coverage
Identifies attack techniques such as script-based exploits, task scheduling abuse, and lateral movement.

8. Automated & Customizable
Automatically collects logs and supports adding custom event IDs or log sources for tailored investigation

![image](https://github.com/user-attachments/assets/9a56da31-b131-4ee8-965e-132e137226f7)

![image](https://github.com/user-attachments/assets/f6cd851d-dfe3-4139-8e8d-cc0106681884)



