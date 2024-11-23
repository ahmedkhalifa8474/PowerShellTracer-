# PowerShellTracer-
Python Script to detect Remote-Connection &amp; PowerShell-Execution using Event IDs and other IOCs
OverView : 
 PowerShellTracer:is a Python script is designed to collect and analyze a variety of security-related and system event logs from a Windows machine. Specifically, it extracts data from PowerShell, security, Sysmon, and scheduled task event logs, providing insight into potential malicious activities. The script focuses on event IDs associated with PowerShell executions, user interactions, system monitoring, and scheduled task activities, which are often used in cybersecurity investigations.

The script allows users to specify a time range (e.g., the last 6 hours) and outputs the relevant event information, including event ID, timestamp, command executed, user, and process ID, into a CSV file called PowerShell.csv. This makes it easy to track and analyze suspicious activities related to PowerShell scripts, task scheduling, and system security events.


#Key Features include:

Collection of PowerShell-related event logs: The script captures event logs related to PowerShell activities, such as script execution, command invocations, and potential malicious behaviors. It supports event IDs like 4103, 4104, 4105, 4106, and others associated with PowerShell events.

Inclusion of security event logs: It extracts security-related event IDs like 4688, 4689, and 4648, which track the creation of new processes, user logons, and account activities, providing insight into potential privilege escalation or lateral movement attempts.

Sysmon event log integration: By incorporating Sysmon event IDs, the script allows for detailed monitoring of system activity, such as process creation (Event ID 1), network connections (Event ID 3), and file creation time (Event ID 11), helping to correlate activities with potential system compromise.

Scheduled task event extraction: The script collects information related to scheduled task events, such as task creation or modifications (Event IDs like 4697 and 4698). These events are useful for identifying persistence mechanisms commonly used by attackers.

Dynamic extraction of command execution details: The script intelligently pulls command strings, user information, and process IDs from event logs, ensuring that the command used to execute potentially suspicious actions is captured for further analysis.

Time-based filtering: Users can specify the time range for event log collection (e.g., the last 6 hours). This allows for targeted investigations and makes it easier to focus on recent activities or specific windows of time.

Output in CSV format: The extracted data is written to a CSV file (PowerShell.csv), making it easy to review, share, and import into other analysis tools (e.g., SIEM systems, spreadsheets). Each event's key details, such as EventID, timestamp, command executed, user, and process ID, are captured for straightforward analysis.

Comprehensive IOC (Indicator of Compromise) coverage: The script includes a wide variety of event IDs across PowerShell, security, Sysmon, and scheduled task logs, allowing for detection of common attack techniques such as script-based exploits, task scheduling abuse, process injection, and lateral movement.

Automated log parsing: The script automatically reads event logs from Windows Event Viewer (including PowerShell, security, and Sysmon logs) and processes them based on specified criteria, eliminating the need for manual log inspection and streamlining the investigation process.

Customizable filtering and extension: The script can be easily extended to include additional event IDs or sources, making it adaptable to various investigation scenarios. Users can tailor the script's behavior to their organization's specific needs by adding custom event IDs or log sources.

Real-time analysis: The script can be run periodically to fetch the latest events, making it useful for ongoing monitoring or ad-hoc investigations into suspicious system behavior.

