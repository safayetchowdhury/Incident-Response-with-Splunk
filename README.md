# Incident Handling and Forensic Analysis with Splunk

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
---

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













