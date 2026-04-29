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




