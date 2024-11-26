import pyfiglet
import win32evtlog
import csv
import time
import re
import requests
from datetime import datetime, timedelta


# Telegram bot API token
API_TOKEN = '7703644930:??????????????LyaeTuXte7CTdBmJjUaCCoR8'
# chat ID
chat_id = "?????8050"

def send_telegram_alert():
    """
    Send a Telegram message to the bot's chat when an IOC is found.
    """
    message = "There is An IOC Found"
    url = f"https://api.telegram.org/bot{API_TOKEN}/sendMessage"
    params = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown'
    }
    try:
        response = requests.post(url, params=params)
        if response.status_code != 200:
            print(f"Failed to send alert: {response.status_code}")
        else:
            print("Alert sent to Telegram.")
    except Exception as e:
        print(f"Error sending message: {e}")


def display_banner():
    """
    Display ASCII art banner with author info.
    """
    banner = pyfiglet.figlet_format("PowerShellTracer")
    author_info = """
    Author: Kh4lifa0x
    LinkedIn: www.linkedin.com/in/ahmed-khalifa-849404266
    """
    print(banner + author_info)


def display_event(event):
    """
    Dynamically display event details in the console.
    """
    print(f"[New Event] EventID: {event['EventID']}, LogType: {event['LogType']}, Timestamp: {event['Timestamp']}, "
          f"Command: {event['Command']}, IOC: {event['IOC']}, User: {event['User']}, ProcessID: {event['ProcessID']}")


def fetch_powershell_events_with_iocs(hours=6):
    """
    Fetch PowerShell events from logs with a time threshold and detect IOCs.
    """
    log_types = [
        "Microsoft-Windows-PowerShell/Operational",
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Sysmon/Operational"
    ]
    event_ids_to_search = {
        4100, 4102, 4103, 4104, 4105, 4106, 1, 3, 4, 8, 10, 11, 12, 13, 15,
        4624, 4625, 4648, 4672, 4673, 4688, 4689, 4697, 4768, 7045
    }
    suspicious_patterns = [
        r"IEX", r"DownloadString", r"Base64", r"Invoke-WebRequest", r"curl", r"wget",
        r"Add-MpPreference", r"Set-MpPreference", r"-NoProfile", r"-ExecutionPolicy Bypass",
        r"New-Object", r"Add-Content", r"Invoke-Expression", r"Set-ExecutionPolicy", r"Out-File",
        r"Invoke-Command", r"Start-Process", r"CreateObject", r"mshta", r"Regsvr32",
        r"powershell.exe", r"psexec", r"ssh", r"cmd.exe", r"wmic", r"Invoke-Item",
        r"Netstat", r"Netsh", r"Clear-DnsClientCache", r"Set-ItemProperty", r"Get-WmiObject",
        r"New-ItemProperty", r"Remove-ItemProperty", r"Regedit", r"RemoteRegistry",
        r"Invoke-ReflectivePEInjection", r"DownloadFile", r"Start-Job"
    ]

    time_threshold = datetime.now() - timedelta(hours=hours)
    events = []

    try:
        for log_type in log_types:
            try:
                log_handle = win32evtlog.OpenEventLog(None, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                while True:
                    records = win32evtlog.ReadEventLog(log_handle, flags, 0)
                    if not records:
                        break

                    for record in records:
                        if record.EventID in event_ids_to_search and record.TimeGenerated >= time_threshold:
                            user_info = "No User Data"
                            if hasattr(record, "StringInserts") and record.StringInserts:
                                user_info = record.StringInserts[1] if len(record.StringInserts) > 1 else "No User Info"
                            command = record.StringInserts[-1] if hasattr(record, "StringInserts") and record.StringInserts else "No Data Available"

                            # Check for IOCs
                            matches = [ioc for ioc in suspicious_patterns if re.search(ioc, command, re.IGNORECASE)]
                            ioc_detected = ", ".join(matches) if matches else "None"

                            event_data = {
                                "EventID": record.EventID,
                                "LogType": log_type,
                                "Timestamp": record.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                                "Command": command,
                                "IOC": ioc_detected,
                                "User": user_info,
                                "ProcessID": record.EventCategory,
                            }
                            events.append(event_data)
                            
                            # If critical IOC is detected, send Telegram alert
                            if ioc_detected != "None":
                                send_telegram_alert()
                win32evtlog.CloseEventLog(log_handle)
            except Exception as e:
                # Skip and suppress errors for Security and Application logs
                if log_type == "Security" and "OpenEventLogW" in str(e):
                    continue
                elif log_type == "Application" and "ReadEventLog" in str(e):
                    continue
                else:
                    print(f"Skipping log type {log_type} due to error: {e}")
    except Exception as e:
        print(f"An error occurred while fetching events: {e}")

    return events


def save_to_csv(events, filename="Enhanced_PowerShell.csv"):
    """
    Save event data to a CSV file.
    """
    try:
        with open(filename, "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["EventID", "LogType", "Timestamp", "Command", "IOC", "User", "ProcessID"])
            writer.writeheader()
            writer.writerows(events)
        print(f"Events have been written to {filename}")
    except Exception as e:
        print(f"Failed to write to file: {e}")


def live_tracking_mode(interval=5):
    """
    Continuously monitor and display new events in real-time.
    """
    print("[*] Starting live tracking mode... Press Ctrl+C to stop.")
    last_event_time = datetime.now() - timedelta(seconds=interval)

    try:
        while True:
            new_events = fetch_powershell_events_with_iocs()
            if new_events:
                for event in new_events:
                    display_event(event)
                last_event_time = datetime.now()  # Update the last event time
            else:
                print("[*] No new events detected...")

            # Add a space between live tracking cycles
            print("\n" + "-"*50 + "\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Live tracking stopped.")


if __name__ == "__main__":
    display_banner()

    # User Interaction
    mode = input("Choose mode (1: Fetch events, 2: Live tracking): ").strip()
    if mode == "1":
        # Fetch and display events
        events = fetch_powershell_events_with_iocs(6)
        if events:
            for event in events:
                display_event(event)
            save_to_csv(events, "Enhanced_PowerShell.csv")
        else:
            print("No events found in the last 6 hours.")
    elif mode == "2":
        # Live tracking mode
        live_tracking_mode(interval=5)
    else:
        print("Invalid choice. Exiting.")
