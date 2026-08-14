# Splunk SOC Detection Project

Built detections against the Splunk BOTS v1 dataset, mapped to MITRE ATT&CK techniques. Includes SPL queries, findings, and screenshots for each detection.

**Tools:** Splunk, Docker, SPL, MITRE ATT&CK
**Dataset:** [Splunk BOTS v1](https://github.com/splunk/botsv1)

---

## Detection 1: Privilege Escalation Volume by Host

**MITRE ATT&CK Mapping:** T1078 (Valid Accounts)

**Sourcetype:** `wineventlog:security`

**Query:**
```spl
index=botsv1 sourcetype=wineventlog:security EventCode=4672 | stats count by ComputerName | sort -count
```

**What it does:**
This query finds which hosts had the most "special privileges assigned" events (EventCode 4672). These events can indicate repetitive system-level and administrative logon attempts and activities. 

**Finding:**
Host `we9041srv.waynecorpinc.local` warrants further investigation and should be looked into as a potentially compromised or over-privileged system due to it having a much higher volume of privilege escalations compared to other hosts in the environment, with 1844 privilege escalation events.

**Screenshot:**
![Privilege Escalation by Host](results/privilege_escalation_detection_by_host.jpg)
