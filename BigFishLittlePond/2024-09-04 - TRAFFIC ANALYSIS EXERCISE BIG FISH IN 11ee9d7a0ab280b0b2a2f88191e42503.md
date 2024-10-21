# 2024-09-04 - TRAFFIC ANALYSIS EXERCISE: BIG FISH IN A LITTLE POND

ASSOCIATED FILES:

- Zip archive of the pcap: [**2024-09-04-traffic-analysis-exercise.pcap.zip**](https://malware-traffic-analysis.net/2024/09/04/2024-09-04-traffic-analysis-exercise.pcap.zip) 1.7 MB (1,697,386 bytes)
- Zip archive of the pcap: [**2024-09-04-traffic-analysis-exercise-alerts.zip**](https://malware-traffic-analysis.net/2024/09/04/2024-09-04-traffic-analysis-exercise-alerts.zip) 453.9 kB (452,950 bytes)

NOTES:

- Zip files are password-protected. Of note, this site has a new password scheme. For the password, see the "about" page of this website.

![2024-09-04-traffic-analysis-exercise-image-01.jpg](2024-09-04-traffic-analysis-exercise-image-01.jpg)

## **SCENARIO**

LAN segment details:

- LAN segment range: 172.17.0[.]0/24 (172.17.0[.]0 through 172.17.0[.]255)
- Domain: bepositive[.]com
- Active Directory (AD) domain controller: 172.17.0[.]17 - WIN-CTL9XBQ9Y19
- AD environment name: BEPOSITIVE
- LAN segment gateway: 172.17.0[.]1
- LAN segment broadcast address: 172.17.0[.]255

## **TASK**

- Write an incident report based on malicious network activity from the pcap and from the alerts.
- The incident report should contains 3 sections:

> Executive Summary: State in simple, direct terms what happened (when, who, what).
> 

> Victim Details: Details of the victim (hostname, IP address, MAC address, Windows user account name).
> 

> Indicators of Compromise (IOCs): IP addresses, domains and URLs associated with the activity.  SHA256 hashes if any malware binaries can be extracted from the pcap.
> 

## **ANSWERS**

- Click [**here**](https://malware-traffic-analysis.net/2024/09/04/page2.html) for the answers.

password- infected_20240904

## Step 1: Initial Investigation

The first alert detected in the provided network capture file is a malware communication. The specific alert is:

```
Count: 48 Event# 3.1504 First seen: 2024-09-04 17:35 UTC
ETPRO TROJAN Win32/Koi Stealer CnC Checkin (POST) M2
172.17.0.99 -> 79.124.78.197

```

This indicates the infected host at IP address `172.17.0.99` is communicating with an external command and control (C2) server at `79.124.78.197` using HTTP POST requests.

## Step 2: Identifying the Host

To identify the infected host:

- Filtered the traffic for `ip.addr == 172.17.0.99 and http`.
- Attempted to identify the hostname through DHCP but was unsuccessful.
- Found the host information using NBNS (NetBIOS Name Service):
    - Hostname: **DESKTOP-RNV09AT**
    - MAC Address: **18:3d:a2:b6:8d:c4**

## Step 3: Identifying the User

Next, we searched for Kerberos traffic to uncover the associated Windows username:

- Applied the filter `kerberos.CNameString` and identified the user as **efletcher** (Andrew Fletcher).

## Step 4: Analyzing C2 Communications

To investigate the C2 communications, we used the following filter to observe traffic between the infected host and the C2 server at `79.124.78.197`:

```
ip.addr == 172.17.0.99 && ip.addr == 79.124.78.197 && http

```

From this, we discovered the following HTTP POST requests being made to the C2 server:

- `POST /foots.php`
- `POST /index.php?id&subid=qIOuKk7U`
- `POST /index.php`

This indicates malicious activity typical of data exfiltration or C2 instructions.

## Step 5: Victim Details Confirmation

Using LDAP traffic (`ldap contains "CN=Users"`), we confirmed that the victim is **Andrew Fletcher** (username: afletcher), operating on the Windows machine **DESKTOP-RNV09AT**.

## Step 6: Conclusion

The infected host is confirmed, and the malicious activity involves the Koi Stealer malware communicating with a known malicious server. While no malware binaries were extracted directly, the analysis of the network traffic provides ample evidence of infection.

---

## Incident Report

### Executive Summary:

On **2024-09-04 at 17:35 UTC**, a Windows machine identified as **DESKTOP-RNV09AT** with the username **efletcher** exhibited signs of infection with the **Koi Stealer** malware. The host initiated communication with a known malicious server, **79.124.78.197**, over HTTP, indicating a possible data exfiltration or command-and-control (C2) activity.

### Victim Details:

- **Hostname**: DESKTOP-RNV09AT
- **IP Address**: 172.17.0.99
- **MAC Address**: 18:3d:a2:b6:8d:c4
- **Windows User Account Name**: afletcher
- **Victim Name**: Andrew Fletcher

### Indicators of Compromise (IOCs):

- **Source IP**: 172.17.0.99
- **Destination IP**: 79.124.78.197
- **Malicious Domain**: [79.124.78.197](http://79.124.78.197/)
- **Alert**: ETPRO TROJAN Win32/Koi Stealer CnC Checkin (POST) M2

### URLs Generating Malicious Traffic:

- 79.124.78.197:80 – POST /foots.php
- 79.124.78.197:80 – POST /index.php?id&subid=qIOuKk7U
- 79.124.78.197:80 – POST /index.php