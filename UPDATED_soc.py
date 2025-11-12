from flask import Flask, request, jsonify
import csv, time, os

app = Flask(__name__)

# Ensure tickets folder exists
os.makedirs("tickets", exist_ok=True)

@app.route("/alert", methods=["POST"])
def alert():
    data = request.get_json(force=True, silent=True) or {}
    result = data.get("result", data)   # Splunk sends results inside "result"

    # Extract fields from your logs
    ts = result.get("Timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
    source = result.get("Source", "N/A")
    severity = result.get("Severity", "N/A")
    event = result.get("EventDescription", "N/A")
    alert_name = result.get("search_name", "SOC Alert")

    # Save into CSV
    ticket_file = "tickets/tickets.csv"
    new_file = not os.path.exists(ticket_file)

    with open(ticket_file, "a", newline="") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["AlertName", "Timestamp", "Source", "Severity", "EventDescription"])
        writer.writerow([alert_name, ts, source, severity, event])

    return jsonify({
        "ok": True,
        "alert": alert_name,
        "Timestamp": ts,
        "Source": source,
        "Severity": severity,
        "EventDescription": event
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
