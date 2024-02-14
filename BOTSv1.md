# BOTSv1 Writeups

### Level 1: Finding Attack Servers

#### BOTSv1 1.1: Scanner Name (5 pts)

Question: What is the brand name of the vulnerability scanner, covered by a green box in the image above?

SPL: `index="botsv1" sourcetype="stream:http" AND Scanner`

![1.1a](../assets/1-1a.png)

![1.1b](../assets/1-1b.png)

**A: `Acunetix`**

#### BOTSv1 1.2: Attacker IP (5 pts)

Question: What is the attacker's IP address?

SPL: *same as above*

![1.2](../assets/1-2.png)

**A: `40.80.148.42`**

#### BOTSv1 1.3: Web Server IP (5 pts)

Question: What is the IP address of the web server serving "imreallynotbatman.com"?

SPL: `index="botsv1" sourcetype="stream:http" AND Scanner` *or* `index="botsv1" sourcetype="stream:http" AND "imnotreallybatman.com"`

![1.3](../assets/1-3.png)

**A: `192.168.250.70`**

#### BOTSv1 1.4: Defacement Filename (10 pts)

Question: What is the name of the file used to deface the web server serving "imreallynotbatman.com"?

>Hints:
>- It was downloaded by the Web server, so the server's IP is a client address, not a destination address.
>- Remove the filter to see all 9 such events. Examine the **uri** values.

SPL: `index="botsv1" sourcetype="stream:http" AND c_ip="192.168.250.70"`

![1.4a](../assets/1-4a.png)


Go to Interesting Fields > `uri` > move to selected field (i.e. `yes`)

![1.4b](../assets/1-4b.png)

**A: `poisonivy-is-coming-for-you-batman.jpeg`**

#### BOTSv1 1.5: Domain Name (10 pts)

Question: What is the fully qualified domain name (FQDN) used by the staging server hosting the defacement file?

>Hints:
>- Examine the 9 events from the previous challenge. Look at the **url** values.

SPL:  *same as above*

![1.5](../assets/1-5.png)

**A: `prankglassinebracket.jumpingcrab.com:1337`**

---
### Level 2: Identifying Threat Actors

#### BOTSv1 2.1: Staging Server IP (10 pts)

Question: What is the IP address of the staging server hosting the defacement file?

>Hints:
>- Search for HTTP GET events containing the target FQDN.

SPL: `index="botsv1" sourcetype="stream:http" AND prankglassinebracket.jumpingcrab.com AND http_method=GET`

![2.1a](../assets/2-1a.png)

![2.1b](../assets/2-1b.png)

**A: `23.22.63.114`**

#### BOTSv1 2.2: Leetspeak Domain (10 pts)

Question: What is the Leetspeak domain found on the staging server? Use a search engine (outside Splunk) to find other domains on the staging server. Search for that IP address. Find a domain with an name in Leetspeak (like "1337sp33k.com").

SPL: *N.A.*

![2.2](../assets/2-2.png)

**A: `po1s0n1vy.com`**

#### BOTSv1 2.3: Brute Force Attack (15 pts)

Question: What is the IP address performing a brute force attack against "imreallynotbatman.com"?

***Initial Try***
SPL: `index="botsv1" sourcetype="stream:http" AND "imreallynotbatman.com" | stats count by src_ip, dest_ip | sort -count`
- obtain results counted by source and destination ip by descending count to pinpoint likely attacker address (source) -> may be both 23.22.x.x or 40.80.x.x
- answer limited to target web site

![2.3a](../assets/2-3a.png)


>Hints
>- Find the 15,570 HTTP events using the POST method.
>- Exclude the events from the vulnerability scanner.
>- Examine the **form_data** of the remaining 441 events.
>- To make a useful table, add this to your query: 
    > **`| table _time, form_data`**

![2.3b](../assets/2-3b.png)

SPL: `index="botsv1" sourcetype="stream:http" AND "imreallynotbatman.com" AND http_method=POST AND (NOT Acunetix) AND "user" in form_data AND "pass" in form_data | table _time, src_ip, dest_ip, form_data`

![2.3c](../assets/2-3c.png)


**A: `23.22.63.114`**

#### BOTSv1 2.4: Uploaded Executable File Name (15 pts)

Question: What is the name of the executable file the attacker uploaded to the server?

>Hints
>- Find the 15,570 HTTP events using the POST method.
>- Exclude the events from the vulnerability scanner.
>- Search for common Windows executable filename extensions.

SPL: `index="botsv1" sourcetype="stream:http" AND "imreallynotbatman.com" AND http_method=POST AND (NOT Acunetix) AND (exe OR dll OR elf)`
- search on the most common executable formats

![2.4a](../assets/2-4a.png)


Next we can do a `Ctrl-F` for `.exe`, `.dll` and `.elf`. The first yields `3791.exe`, while the latter two yield no results.

![2.4b](../assets/2-4b.png)

**A: `3791.exe`**

---
### Level 3: Using Sysmon and Stream

#### BOTSv1 3.1: MD5 (10 pts)

Question: What is the MD5 hash of the uploaded executable file?

SPL: ``

A:

#### BOTSv1 3.2: Brute Force (10 pts)

Question: What was the first brute force password used?

SPL: ``

A:

#### BOTSv1 3.3: Correct Password (10 pts)

Question: What was the correct password found in the brute force attack?

SPL: ``

A:

#### BOTSv1 3.4: Time Interval (10 pts)

Question: How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? Round to 2 decimal places.

SPL: ``

A:

#### BOTSv1 3.5: Number of Passwords (10 pts)

Question: How many unique passwords were attempted in the brute force attack?

SPL: ``

A:

### Level 4: Analyzing a Ransomware Attack

#### BOTSv1 4.1: IP Address (5 pts)

Question: What was the most likely IP address of we8105desk on 24AUG2016?

SPL: ``

A:

#### BOTSv1 4.2: Signature ID (5 pts)

Question: Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. (No punctuation, just 7 integers.)

SPL: ``

A:

#### BOTSv1 4.3: FQDN (15 pts)

Question: What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

SPL: ``

A:

#### BOTSv1 4.4: Suspicious Domain (15 pts)

Question: What was the first suspicious domain visited by we8105desk on 24AUG2016?

SPL: ``

A:

#### BOTSv1 4.5: VB Script (15 pts)

Question: During the initial Cerber infection, a VB script is run. What is the name of the first function defined in the VB script?

SPL: ``

A:

#### BOTSv1 4.6: Field Length (15 pts)

Question: During the initial Cerber infection, a VB script is run. What is the length in characters of the value of the field containing the VB script?

SPL: ``

A:

#### BOTSv1 4.7: USB key (15 pts)

Question: What is the name of the USB key inserted by Bob Smith?

SPL: ``

A:

#### BOTSv1 4.8: Server Name (5 pts)

Question: Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the domain name of the file server?

SPL: ``

A:

#### BOTSv1 4.9: IP Address (15 pts)

Question: Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IP address of the file server?

SPL: ``

A:

#### BOTSv1 4.10: PDFs (20 pts)

Question: How many distinct PDFs did the ransomware encrypt on the remote file server?

SPL: ``

A:

#### BOTSv1 4.11: Process ID (15 pts)

Question: The VBscript found above launches 121214.tmp. What is the ParentProcessId of this initial launch?

SPL: ``

A:

#### BOTSv1 4.12: Text Files (15 pts)

Question: The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

SPL: ``

A:

#### BOTSv1 4.13: File Name (15 pts)

Question: The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

SPL: ``

A:

#### BOTSv1 4.14: Obfuscation (10 pts)

Question: Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?

SPL: ``

A: