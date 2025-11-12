# 🛡️ SOC Finance Threat Detection & Automation

A complete **Security Operations Center (SOC) monitoring and automation system** designed for financial sector environments.  
It combines **Flask**, **Splunk**, and **VirusTotal API** to detect, enrich, and visualize cyber threats in real time.

---

## 🚀 Project Highlights

- 🔍 Real-time monitoring of IDS, Firewall, VPN, and Email Security logs  
- 🧠 Automatic enrichment via **VirusTotal API** for IP/domain intelligence  
- 📊 **Splunk Dashboards** display total alerts, malware events, port scans, and login anomalies  
- 🧾 Generates **NIST CSF-aligned compliance reports**  
- ⚙️ Built with a **Flask automation API** that creates tickets and enriches events dynamically  

---

## 🧩 Tech Stack

| Layer | Tools Used |
|-------|-------------|
| Backend | Python (Flask), dotenv, requests |
| Data | CSV, JSON |
| Visualization | Splunk Enterprise |
| Threat Intel | VirusTotal, GeoIP |
| Compliance | NIST CSF Mapping |
| Automation | REST API + CSV ticketing |

---

## ⚙️ How It Works

1. **Log Sources** — Firewall, IDS, VPN, and Email Gateway events are indexed in Splunk.  
2. **Automation API** — Flask service receives IP/domain indicators.  
3. **Threat Enrichment** — VirusTotal & GeoIP APIs provide threat reputation data.  
4. **Visualization** — Splunk dashboards aggregate and visualize enriched events.

---

## 📊SOC Metrics

| Metric | Value |
|---------|-------|
| Total Alerts | **120** |
| Critical Alerts | **33** |
| Malware Detections | **4** |
| Port Scans | **6** |
| VPN Failed Logins | **4** |

---

## 🖼️ Screenshots

| Feature | Screenshot |
|----------|-------------|
| **Flask SOC Automation Service (Python API)** |

<img width="1902" height="833" alt="image" src="https://github.com/user-attachments/assets/80e73dee-86bd-4b4a-9856-7d73b75cfac1" />

| **Critical Event Alerts – Splunk Search** |

<img width="1895" height="667" alt="image" src="https://github.com/user-attachments/assets/0f9f3e7e-7d7a-4bb5-bd4c-3f8772b18d5b" />

| **Malware Detection Alerts – IDS (Snort)** | 

<img width="1905" height="619" alt="image" src="https://github.com/user-attachments/assets/0abfc2ba-09b5-4790-bd50-ce3dbd213bb7" />

| **Port Scan Detection – Firewall Events** | 

<img width="1916" height="614" alt="image" src="https://github.com/user-attachments/assets/854ac54c-efe4-4c59-8f74-365162807848" />

| **VPN Failed Logins – Remote Access Server** | 

<img width="1914" height="632" alt="image" src="https://github.com/user-attachments/assets/12300c20-fe2d-4f17-be76-68b0b31c6bf8" />

| **Environment Keys (.env – VirusTotal + GeoIP)** | 

<img width="1364" height="511" alt="image" src="https://github.com/user-attachments/assets/c0652ebe-a27f-4bba-8d5b-2bf1c7c73d0c" />

| **SOC Dashboard Metrics Summary** | 

<img width="1889" height="576" alt="image" src="https://github.com/user-attachments/assets/42ed063b-bdc1-41fc-a316-529dc99a2dbb" />


| **SOC_FinanceUK Overview Dashboard (Splunk)** | 
<img width="1906" height="681" alt="image" src="https://github.com/user-attachments/assets/d2f6bc87-0c40-46cf-8370-b8832ed0cf28" />




## 🧰 Quick Setup


# 1️⃣ Clone the repository
git clone https://github.com/<yourusername>/soc-finance-automation.git
cd soc-finance-automation

# 2️⃣ Create environment variables
echo "VT_KEY=your_virustotal_api_key" > .env
echo "geoip_key=your_geoip_api_key" >> .env

# 3️⃣ Install dependencies
pip install -r requirements.txt

# 4️⃣ Run Flask SOC Service
python UPDATED_soc.py


🔒 Compliance Focus

This project aligns with the NIST Cybersecurity Framework (CSF)
✅ Identify ✅ Protect ✅ Detect ✅ Respond ✅ Recover

👤 Author

**Shuaib Salami A.**
Cybersecurity consultant



