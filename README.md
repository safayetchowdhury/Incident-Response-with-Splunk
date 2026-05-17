# Incident Response with Splunk

## Project Overview
Welcome! This lab demonstrates the use of Splunk for incident handling and forensic analysis within a real-world scenario. The investigation focuses on a targeted attack and subsequent defacement of the imreallynotbatman.com web server. By mapping the adversary's movements to the 7 phases of the Cyber Kill Chain, I’ve reconstructed the attack lifecycle by leveraging advanced Splunk SPL queries and OSINT intelligence (via VirusTotal and Robtex) to unmask the infrastructure behind the breach.

### What can we learn from this lab?
* Cyber kill chain phases
* Effectively utilizing Splunk Queries
* Leveraging OSINT
* Importance of host-centric and network-centric log sources

## Environment & Dataset
This investigation utilizes the industry-standard Splunk "Boss of the SOC" (BOTS) v1 dataset. The scenario simulates a targeted attack on Wayne Enterprise and its public-facing domain, imreallynotbatman.com.

> [!IMPORTANT]
> **Time Range Configuration:** Because this is a historical dataset from 2016, you must set the Splunk Time Range Picker to "All Time" for your searches to return results. If the picker is set to "Last 24 Hours," no events will be visible.

## Scenario Overview
Wayne Enterprise, a major corporate entity, was recently the victim of a cyber-attack. Wayne Enterprise's official website is http://www.imreallynotbatman.com. A trademark associated with the attackers is now displayed on their website, in addition to the message "YOUR SITE HAS BEEN DEFACED" as shown below. Wayne Enterprise uses Splunk as their Security Information and Event Management solution, which I’ll be using throughout the investigation.
<img width="1006" height="564" alt="image" src="https://github.com/user-attachments/assets/16566c45-3cf3-4f08-b0e3-f391d938a9a8" />
## Investigation Scope

### Logs I used:
* Webserver
* Firewall
* Suricata
* Sysmon

I’ll talk a little about 7 phases of the Cyber Kill Chain here before we begin. The phases are:
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objectives
<img width="1193" height="684" alt="image" src="https://github.com/user-attachments/assets/46ab0c8d-8b1f-43a4-ab6b-2db1f226f93b" />

> [!NOTE]
> Please note that it isn’t necessary to follow this sequence of the phases while investigating. Let’s dive in!

## Reconnaissance Phase
Reconnaissance is the phase in which an attacker gathers intelligence about their target, which could be systems, software, web application they use and can be information about employees or location. 

### Step 1: Finding logs
I’m going to look for event logs in the index `botsv1` containing the term `imreallynotbatman.com`.

**Search Query:**
```splunk
index=botsv1 imreallynotbatman.com
```

<img width="1125" height="638" alt="image" src="https://github.com/user-attachments/assets/60e984a6-085a-467e-8b1f-262b7101ab89" />

I found four log sources in the sourcetype field, which are:
* `suricata`
* `stream:http`
* `fortigate:utm`
* `iis`

### Step 2: Initial Source Identification
Here I’ll be filtering `stream:http` logs for the domain `imreallynotbatman.com` to isolate and identify the source IP address involved in the initial reconnaissance. 

**Search Query:**
```splunk
index=botsv1 imreallynotbatman.com sourcetype=stream:http
```
<img width="1073" height="562" alt="image" src="https://github.com/user-attachments/assets/4cf646af-b8eb-4849-948f-32ca544850b8" />

As we can see, I found two IPs in the `src_ip` field `40.80.148.42` and `23.22.63.114`. The first IP has a higher percentage which is 93.4% and most likely I have found the attacker. But I want to go further to see if my suspicion is right. 

### Step 3: Validating Reconnaissance via Alert Signature

**Search Query:**
```splunk
index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata
```
<img width="1125" height="463" alt="image" src="https://github.com/user-attachments/assets/64decfad-90d1-49ae-9305-d954d6929fba" />

This query filters the suricata logs for the IP `40.80.148.42` that I was suspecting to have malicious intent. After analyzing the alert.signature field, the CVE Identifiers confirm that very IP as the source of exploit attempts. 

## Exploitation Phase
In this phase, I’ll analyze the exploit attempts of the attacker to check whether the exploitation attempts were successful. So far, I found two IP addresses from our first phase but one of the IPs which is **40.80.148.42** was attempting to scan the server with IP **192.168.250.70**.

### Step 1: Counting Requests
I will now examine how many requests each IP made to the server and for this I will be using the query below:

**Search Query:**
```splunk
index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort -Requests
```
<img width="1125" height="397" alt="image" src="https://github.com/user-attachments/assets/96fa1f1b-c846-412d-8a2c-f167bd41d5ab" />

This query uses the stats function to display the count of the IP addresses in the field `src_ip`.
### Step 2: Inbound Traffic Analysis
Here I’ll narrow down the result to show requests sent to our server with IP `192.168.250.70`.

**Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
```
<img width="920" height="541" alt="image" src="https://github.com/user-attachments/assets/1567d797-5d31-4e4b-a2ee-c81b0b791f45" />

The `src_ip` distribution identifies three IP addresses, one internal and two external, initiating HTTP traffic. 

To further analyze the nature of these connections, I examined the `http_method` field and observed that most of the requests were coming to that server through **POST** requests, which is shown below:
<img width="1027" height="451" alt="image" src="https://github.com/user-attachments/assets/fd901801-bb5d-415d-8dc4-0fe0ac4126ef" />
Now I’ll go a little further to see the type of traffic coming through the POST request. To do this I’ll narrow down to the field `http_method=POST` like the query below:

**Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST
```

<img width="1125" height="554" alt="image" src="https://github.com/user-attachments/assets/67d8ff80-c59e-4933-b591-6e98d41c1c07" />

### Step 3: Joomla CMS
There are some fields on the left panel, which are called interesting fields. Some of the fields are:
* `src_ip`
* `form_data`
* `http_user_agent`
* `uri`

**Joomla** is mentioned multiple times in fields like `uri`, `uri_path`, and `http_referrer`, indicating that the server is using the Joomla CMS (Content Management System). Research identifies the Joomla CMS administrative portal at `/joomla/administrator/index.php`. 

Monitoring traffic to this specific URI is critical, as it represents a high-value target for brute-force attempts and unauthorized access. I will now narrow down the search to see requests sent to the login portal.

**Search Query:**
```splunk
index=botsv1 imreallynotbatman.com sourcetype=stream:http dest_ip="192.168.250.70" uri="/joomla/administrator/index.php"
```
<img width="899" height="809" alt="image" src="https://github.com/user-attachments/assets/7cb5757d-58d6-41ed-bfce-9632e9025722" />

The `form_data` field contains the requests sent through the form on the admin panel page, which features a login portal. I suspect the attacker may have tried multiple credentials to gain access to the administrative interface. 

To confirm my suspicion and analyze the patterns effectively, I will refine the search into a summary table using the following query:

**Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" 
| table _time uri src_ip dest_ip form_data
```
<img width="1125" height="593" alt="image" src="https://github.com/user-attachments/assets/0b5d4c9f-fd52-4918-806f-48b20d174873" />

By analyzing the `username` and `passwd` fields, I identified a brute-force attack originating from IP `23.22.63.114`. The attacker targeted the `admin` account with a high volume of password permutations, confirming a systematic credential-guessing attempt. 

### Step 4: Extraction and Filtering
The raw logs show that the `username` and `passwd` fields within `form_data` are not properly parsed. To isolate the relevant events, I refined the search using a wildcard filter `form_data=*username*passwd*`. This specifically captures logs where both credential fields are present in the `form_data`.

**Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd* | table _time uri src_ip dest_ip form_data
```
<img width="1125" height="529" alt="image" src="https://github.com/user-attachments/assets/13a59764-c589-4dc0-9e04-53469aa15c2d" />

Now I will apply a **Regular Expression (Regex)** to isolate and extract every password attempt into a new field called `creds`. 

Using the command `rex field=form_data "passwd=(?<creds>\w+)"`, I can transform the messy `form_data` string into a clean, focused view of the specific password strings used during the brute-force attack.

**Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" 
| table src_ip creds
```
<img width="1125" height="860" alt="image" src="https://github.com/user-attachments/assets/385a5ea1-38fd-425f-8b70-8e4166793829" />

### Step 4: Manual vs. Automated Attribution
After extracting the credentials used against the `admin` account, an analysis of the `http_user_agent` field reveals two distinct attack vectors.
<img width="1056" height="816" alt="image" src="https://github.com/user-attachments/assets/74b04866-7485-4d06-8da6-808350722dc6" />

The primary source, IP `23.22.63.114`, utilized a Python script to execute a high-volume, automated brute-force attack. Conversely, a single login attempt for the password `batman` originated from IP `40.80.148.42` via a Mozilla browser. 

I will now refine the search to correlate these different source IPs and analyze the timing of their requests.

**Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" 
| table _time src_ip uri http_user_agent creds
```
<img width="1125" height="600" alt="image" src="https://github.com/user-attachments/assets/66f57b31-fdff-488b-adc4-78b767ca6f2a" />

Here I can correlate these different source IPs with their respective tools, distinguishing between automated scripts and manual, human-driven intervention.

| Source IP | Tool (User-Agent) | Action Type |
| :--- | :--- | :--- |
| `23.22.63.114` | `Python-urllib` | **Automated** (High volume brute-force) |
| `40.80.148.42` | `Mozilla/5.0` | **Manual** (Targeted credential testing) |

---
## Installation Phase
After the brute-force attack succeeded, the investigation moves to the **Installation Phase**. This is when an attacker tries to stay in the system by installing a backdoor or malicious app, a tactic also known as gaining **persistence**.

### Step 1: Payload Source Correlation
I already found evidence that `imreallynotbatman.com` was compromised by a Python script guessing the password. Now I need to see if any malicious programs were uploaded to the server from the attacker's IPs. To start the hunt, I will filter all HTTP traffic going to the server `192.168.250.70` for files ending in `.exe`.

**Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
```
<img width="1125" height="522" alt="image" src="https://github.com/user-attachments/assets/85e37247-02ec-46d6-a53c-fa6b84f64d9e" />

I will now cross-reference these files with the attacker's previously identified IP addresses. By selecting the filename in Splunk and checking the `c_ip` (Client IP) field, I can confirm if these malicious uploads originated from the same source as the brute-force attack.

**Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" part_filename{}="3791.exe"
```
<img width="1000" height="541" alt="image" src="https://github.com/user-attachments/assets/26165d98-b4e9-469d-850a-65059eda7c38" />

By checking the `c_ip` field, I confirmed that the malicious files were uploaded from `40.80.148.42`. This is a critical finding because it connects the manual login attempt identified earlier directly to the installation of malware. This proves the attacker successfully progressed from testing credentials to delivering a functional payload.

### Step 2: Execution Analysis
I found that `3791.exe` was successfully uploaded; the next logical step is to determine if it was actually executed. To investigate this, I will shift my search from network traffic to host-centric logs to identify process creation events associated with this file.

**Search Query:**
```splunk
index=botsv1 "3791.exe"
```
<img width="846" height="545" alt="image" src="https://github.com/user-attachments/assets/8afc56ce-a03a-46cf-a764-241cdf13e811" />

I found traces of the executable 3791.exe across several host-centric sources, including Sysmon, WinEventLog, and fortigate_utm.
To confirm if the file actually ran, I'm focusing on Sysmon logs. Specifically, I am looking for EventCode=1, which indicates a Process Creation event. This will provide the details I need, like the full command line and file hashes to prove the program was executed on the system.
Why this matters:
•	Sysmon Event ID 1: This is the primary indicator for process starts in Windows environments.
•	Evidence: If `3791.exe` appears under this Event ID, it confirms the installation was successful and the malware is now active.
**Search Query:**
```splunk
index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1
```
<img width="1125" height="763" alt="image" src="https://github.com/user-attachments/assets/7d1a5d8a-8d0e-4b4d-b83e-04c59d5137ff" />

By correlating the **EventID 1** (Process Creation) with the **CommandLine** activity and the extracted **MD5 hash**, I have confirmed that the attacker successfully executed the malicious payload on the server. 

<img width="1125" height="227" alt="image" src="https://github.com/user-attachments/assets/73300c5d-2358-431b-a35d-04f728a12f63" />

Above I have shown the extracted **MD5 hash** and this concludes the installation phase.

## Action on Objectives Phase
Since the website was defaced, I need to investigate what content was modified. I’ll start by analyzing **Suricata** logs to map the traffic flow between external IPs and the webserver at `192.168.250.70`. This will help me pinpoint exactly how the attacker interacted with the site to change its appearance.

**Search Query:**
```splunk
index=botsv1 dest=192.168.250.70 sourcetype=suricata
```
<img width="1125" height="679" alt="image" src="https://github.com/user-attachments/assets/2c9959e2-fdd1-4f08-a99c-96bfb6aff034" />

The Suricata logs don't show any external IPs hitting the server. I'll now reverse the query to see if the server is originating any outbound communication.

**Search Query:**
```splunk
index=botsv1 src=192.168.250.70 sourcetype=suricata
```
<img width="1125" height="862" alt="image" src="https://github.com/user-attachments/assets/644609a7-5ada-434e-9a0a-608791c2aea3" />

It is highly unusual for a web server to originate traffic, as it should primarily be a destination for client requests. However, these logs show the server initiating outbound connections to three external IP addresses.
Because of the high volume of traffic involved, I need to pivot and examine each destination IP individually, which will allow me to identify the specific nature of these communications.

**Search Query:**
```splunk 
index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
```
<img width="1125" height="734" alt="image" src="https://github.com/user-attachments/assets/08fd9552-cec8-4bff-95e7-01c776c27df3" />

The URL field contains two PHP files and a suspicious image. Given the provocative name of the jpeg file (`Poisonivy-is-coming-for-you-batman.jpeg`) I'll update my query to track the source of this file.

 **Search Query:**
```splunk 
index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url
```

<img width="1125" height="373" alt="image" src="https://github.com/user-attachments/assets/78dd2b09-afdc-4b25-b58a-e64cbec26ba9" />

The evidence confirms that the defacement was triggered by the file `poisonivy-is-coming-for-you-batman.jpeg`. This malicious asset was pulled directly from the attacker’s host, `prankglassinebracket.jumpingcrab.com`, providing a clear link between the external source and the visual compromise of the site.

## Command & Control (C2) Phase
Before the defacement, the attacker uploaded a malicious payload using a Dynamic DNS (DDNS) domain to mask their infrastructure. My next objective is to identify the specific IP mapped to that DNS record. To trace this communication, I’ll analyze network-centric logs, starting with `fortigate_utm` to review firewall activity before pivoting to other sources.

**Search Query:**
```splunk
index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg"
```

<img width="1125" height="520" alt="image" src="https://github.com/user-attachments/assets/f5a8da28-eda1-47d4-a967-fa6521c16f66" />

The `fortigate_utm` logs display the source and destination IPs, with the url field providing the **FQDN**. This field allows me to map the attacker's domain directly to the specific IP address used for the malicious download.

<img width="1125" height="395" alt="image" src="https://github.com/user-attachments/assets/1462b635-79da-4b59-b884-70117565ee96" />

I'll cross-reference the `stream:http` logs to granularly verify the forensic link between the attacker's IP and the malicious host.

 **Search Query:**
```splunk
index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "poisonivy-is-coming-for-you-batman.jpeg" src_ip=192.168.250.70
```

<img width="1125" height="809" alt="image" src="https://github.com/user-attachments/assets/6acb7be4-cefe-4d6e-b5d5-c9a90568a2f2" />

The suspicious domain is now confirmed as the `Command and Control (C2)` server used by the attacker for post-compromise communication.

## Weaponization Phase
Attackers weaponize by staging malware, spoofed domains, and C2 infrastructure. I will now use **OSINT** to investigate `prankglassinebracket.jumpingcrab.com`, uncovering the IPs and intelligence necessary to identify infrastructure pre-staged against Wayne Enterprise.

### Robtex Analysis
By searching **Robtex**, I’ve identified the IP addresses and subdomains linked to the attacker's infrastructure. The analysis reveals three primary IPs— `69.197.18.183`, `70.39.97.227`, and `169.47.130.85` —along with a list of sibling domains that may be pre-staged for further malicious activity.

**Reference:** [Robtex DNS Lookup](https://www.robtex.com/dns-lookup/prankglassinebracket.jumpingcrab.com)

<img width="728" height="1044" alt="image" src="https://github.com/user-attachments/assets/5ae94f1e-550c-4a53-b8a1-baba648b607a" />

Searching the IP address `23.22.63.114` on Robtex reveals a cluster of domains mimicking Wayne Enterprise. Hostnames such as `waynecorpnc.com`, `waynecorpinc.com`, and `wanecorpinc.com` are clear examples of **typosquatting**, likely staged by the adversary to deceive users during the weaponization phase of the attack.

**Reference:** [Robtex IP Lookup - 23.22.63.114](https://www.robtex.com/ip-lookup/23.22.63.114)

<img width="892" height="552" alt="image" src="https://github.com/user-attachments/assets/5f437bd2-adc7-4085-a208-88d56bbad4ac" />

### VirusTotal Analysis
Searching the IP on **VirusTotal**, a premier OSINT tool for analyzing suspicious assets, reveals a list of associated domains under the ‘RELATIONS’ tab. 

These findings confirm the presence of multiple look-alike domains mimicking "Wayne Enterprise" providing further evidence that the adversary had staged a comprehensive infrastructure to accomplish their objectives. This level of preparation suggests a sophisticated, targeted campaign rather than a random opportunistic attack.

<img width="1059" height="969" alt="image" src="https://github.com/user-attachments/assets/ec1cb8dd-ff41-4c7c-b6be-ef8eca10efe5" />

In the domain list, we saw the domain that is associated with the attacker `www.po1s0n1vy.com`. Let me search for this domain on VirusTotal.

<img width="909" height="916" alt="image" src="https://github.com/user-attachments/assets/ac34dddb-422d-4b65-841d-f254cee31eb6" />

I have successfully unmasked the adversary's pre-positioned infrastructure. This concludes the analysis of the Weaponization phase, providing a complete view of the tools and deceptive assets prepared for the attack against Wayne Enterprise.

## Delivery Phase
In the **Delivery Phase**, attackers deploy malware via diverse vectors to secure initial access. Using previously identified IPs and domains, I will leverage OSINT and threat-hunting platforms to uncover linked malware. 

Since the "Poison Ivy" group is known to utilize secondary attack vectors if initial attempts fail, I will correlate internal logs with threat intelligence to fully map their methodology.

#### OSINT Resources Utilized:
* **VirusTotal**
* **ThreatMiner**
* **Hybrid-Analysis**

I’ll start the investigation by searching for the IP `23.22.63.114` on **ThreatMiner** to identify any previously seen malware samples associated with this host.

**Reference:** [ThreatMiner Host Lookup - 23.22.63.114](https://www.threatminer.org/host.php?q=23.22.63.114#gsc.tab=0&gsc.q=23.22.63.114&gsc.page=1)

<img width="1125" height="848" alt="image" src="https://github.com/user-attachments/assets/676c0005-08f7-4452-9cb2-5d374072bfeb" />

Three files are linked to this IP, including a malicious payload with the **MD5 hash c99131e0169171935c5ac32615ed6261**. 
As shown in the image below, by analyzing this hash's metadata, I can uncover critical details about the file's behavior and its role in the adversary's delivery strategy.

<img width="1125" height="546" alt="image" src="https://github.com/user-attachments/assets/d76b4066-49af-4dda-ac23-68d041724c50" />

### VirusTotal: Malware Metadata Analysis
By analyzing the specific file hash on **VirusTotal**, I accessed the **Details** tab to extract critical metadata about the malware payload. 

**Reference:** [VirusTotal File Analysis - 9709...34a8](https://www.virustotal.com/gui/file/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8/community)

<img width="1125" height="631" alt="image" src="https://github.com/user-attachments/assets/a0c16e34-0973-493c-b325-27d12c540c57" />

### Hybrid-Analysis: Behavioral Sandbox Breakdown
**Hybrid-Analysis** is a powerful behavioral analysis platform that executes malware in a sandbox to observe its real-time activity. It provides a comprehensive forensic breakdown, allowing me to see exactly what the payload does once it hits a target system. 

Key insights provided by this behavioral analysis include:
* **Network Communication:** Identifying DNS requests and contacted hosts (including country mapping).
* **Forensic Markers:** Identifying hardcoded strings, DLL imports/exports, and Mutex information.
* **Threat Intelligence:** Mapping activity to the **MITRE ATT&CK** framework and identifying specific malicious indicators.
* **Visual Evidence:** Reviewing runtime screenshots to observe the malware's interaction with the operating system.

<img width="1125" height="635" alt="image" src="https://github.com/user-attachments/assets/18770417-3c0f-4d8f-a149-1ab0c934f3ea" />

<img width="1125" height="635" alt="image" src="https://github.com/user-attachments/assets/e8b054e9-01bf-4360-bbf5-c6c7c45892b2" />

# Investigation Wrap-Up: The Wayne Enterprise Incident

This report concludes the end-to-end forensic analysis of the attack on `imreallynotbatman.com`. By mapping fragmented logs to the **Cyber Kill Chain**, I transformed raw data into a clear narrative of the adversary's lifecycle.

## Final Incident Reconstruction

### 1. Reconnaissance & Exploitation
The attack began with heavy probing of the external web infrastructure. I identified persistent scanning and brute-force activity originating from two primary attacker-controlled IPs.
* **The Breach:** Out of 142 unique brute-force attempts, the adversary successfully authenticated once, gaining unauthorized access to the web server.
* **Primary Attribution IPs:** `40.80.148.42` (Scanning/Access) and `23.22.63.114` (Brute-force origin).

### 2. Installation & Actions on Objectives
Once access was established, the adversary moved quickly to solidify their presence and carry out their visible goal: defacing the company's public image.
* **Persistence:** Sysmon logs captured the upload of a malicious executable, `3791.exe`. I extracted the **MD5 hash** for further forensic pivot and signature-based blocking.
* **The Defacement:** The attacker replaced legitimate site content with a provocative image, `poisonivy-is-coming-for-you-batman.jpeg`, confirming the completion of their primary objective.

### 3. Weaponization (Infrastructure Analysis)
Using OSINT tools like **Robtex** and **VirusTotal**, I looked beyond internal logs to map the adversary's staging environment.
* **Command & Control (C2):** The adversary utilized the Dynamic DNS domain `prankglassinebracket.jumpingcrab.com` to mask their physical location.
* **Deception Assets:** I uncovered a cluster of typosquatted domains (e.g., `waynecorpnc.com`, `wanecorpinc.com`) pre-staged for potential phishing or credential harvesting.

### 4. Delivery (Secondary Attack Vectors)
Analysis revealed that the adversary had backup plans if initial attempts failed.
* **Malware Discovery:** I identified a secondary payload, `MirandaTateScreensaver.scr.exe`, linked to the attacker's infrastructure.
* **Forensic Signature:** The MD5 hash `c99131e0169171935c5ac32615ed6261` was identified as a critical **Indicator of Compromise (IoC)** for future threat-hunting.

---

## Final Reflection
This investigation highlights the importance of **multi-layered visibility**. By correlating Splunk network telemetry with host-based Sysmon logs and external Threat Intelligence, I was able to see not just what happened, but how the adversary planned their campaign.

What started as a simple brute-force entry ended in a full-scale defacement. I successfully unmasked the **Poison Ivy** group as the culprit, exposing a sophisticated web of pre-staged infrastructure and secondary malware that proved their intentions went far beyond a single hacked homepage. 

### Connect & Explore

**GitHub**: Thank you for following along! This lab is part of my ongoing commitment to mastering incident response and forensic analysis. I’m constantly adding new labs and documentation, check back soon for upcoming projects! Check out my existing works below: 
*  [**SQL-Based Security Incident Investigation**](https://github.com/safayetchowdhury/SQL-based-Security-Incident-Investigation)
*  [**Wireshark-and-Nmap-Packet-Analysis-and-Network-Reconnaissance**](https://github.com/safayetchowdhury/Wireshark-and-Nmap-Packet-Analysis-and-Network-Reconnaissance)


**LinkedIn:** I’d love to **[connect](https://www.linkedin.com/in/chowdhurysafayet/)**! If you’re working in information security or are interested in these methodologies, let's discuss how we can improve security posture together.












