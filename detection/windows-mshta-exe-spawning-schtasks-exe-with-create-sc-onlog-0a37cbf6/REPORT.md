# Threat Hunt: mshta.exe spawning schtasks.exe with /Create /SC ONLOGON flags (2026-05-26)

## Disposition
INCONCLUSIVE · **Severity:** MED · **Confidence:** 0.35

## Executive Summary
Hunt for mshta.exe spawning schtasks.exe with /Create /SC ONLOGON flags to establish persistence in AppData\Roaming was initiated but terminated due to a critical veto from the FP Hunter persona (score 0.3). The RedTeam review identified unresolved false-positive risks in enterprise environments where legitimate IT automation, third-party installers, and red-team exercises commonly use identical command-line patterns. Query execution was halted before results could be analyzed. The hypothesis remains technically sound but requires additional disprove conditions and baseline tuning before deployment.

## Source
- **Report:** R4sammy/apex-detections PROD switch validation hunt
- **URL:** https://www.elastic.co/security-labs/r4sammy-prod-validation-2026-05-26
- **Source tier:** prod-switch-validation
- **Published:** 2026-05-26
- **Triaged hunt-worthy at:** 0.87 value score, 0.91 feasibility score

## Hypothesis
Windows mshta.exe spawning schtasks.exe with /Create /SC ONLOGON flags and task path in AppData\Roaming

This hypothesis targets a persistence technique where mshta.exe (HTML Application host) spawns schtasks.exe to create a scheduled task that executes on user logon, with the payload stored in the user's AppData\Roaming directory. The scheduled task name often masquerades as a legitimate Microsoft service (e.g., MicrosoftEdgeUpdateCore).

## Behavior Tested
- **Kind:** LOLBin
- **Description:** mshta.exe spawned cmd.exe or powershell.exe which then executed schtasks.exe with /Create /SC ONLOGON flags to establish a scheduled task masquerading as MicrosoftEdgeUpdateCore, pointing to a payload in AppData\Roaming\update.bat or update.vbs
- **MITRE ATT&CK TTPs:** T1218.005 (Signed Binary Proxy Execution: Mshta), T1053.005 (Scheduled Task/Job: Scheduled Task), T1036.004 (Masquerading: Masquerade Task or Service)
- **Data sources:** process_creation, sysmon_event_1, scheduled_task
- **Tradecraft:**
  - Parent process: mshta.exe
  - Child process: cmd.exe or powershell.exe
  - Command-line patterns: schtasks.exe /Create, /TN MicrosoftEdgeUpdateCore, /SC ONLOGON, /TR
  - File paths: C:\Users\<user>\AppData\Roaming\update.bat, C:\Users\<user>\AppData\Roaming\update.vbs
  - Scheduled task name masquerades as legitimate Microsoft Edge update service; payload path filtered to user profile directories

## Hunt Execution

### RedTeam Review
The hunt was subjected to multi-persona RedTeam review before query execution. Aggregate score: 0.595 with veto flag set.

**Attribution Skeptic (score 0.92, no veto):** Approved the hypothesis as behavior-based with zero actor attribution language. Noted that the hypothesis correctly describes a technique without naming threat groups, which is the appropriate approach for detection engineering.

**FP Hunter (score 0.3, VETO):** Identified critical false-positive risks:
- mshta.exe is commonly used in enterprise environments for legitimate software deployment and IT automation
- Red-team exercises frequently utilize mshta.exe to simulate attack scenarios
- Third-party software installers may use mshta.exe to create scheduled tasks, particularly in legacy systems
- Proposed disprove conditions do not adequately suppress legitimate use cases
- Reliance on specific command-line arguments does not account for variations in legitimate usage

**Source Bias Auditor (score 0.8, no veto):** Found minimal commercial bias. The hypothesis appears sourced from open-source threat intelligence rather than vendor product documentation. Technical specificity suggests multiple independent researcher observations.

**Timing Tester (score 0.5, no veto):** Flagged lack of defined timing constraints between mshta.exe execution and schtasks.exe spawn. The absence of a tight temporal bound risks correlating unrelated events in high-noise environments. Recommended strict temporal constraint (seconds) and correlation with network connection events.

**Alternative Generator (score 0.55, no veto):** Identified five plausible legitimate scenarios that would produce identical observables:
1. Internal IT automation scripts using mshta.exe for line-of-business application deployment
2. Third-party software updaters (SMB clients, printer drivers, endpoint protection agents) employing mshta.exe
3. Developer workstations running local convenience scripts for builds or test harnesses
4. Misconfigured Group Policy Preference or SCCM packages deploying tasks via mshta.exe
5. Authorized red-team exercises intentionally mimicking the technique

**Evidence Gap (score 0.5, no veto):** Noted missing baseline data on normal mshta.exe → schtasks.exe event rates. Identified lack of contingency for deleted or encrypted payload files. Recommended establishing baseline over 90-day window and specifying required fields for query results.

### Queries
Query execution was halted due to FP Hunter veto. No queries were run against production data.

**Planned Query Q1 (not executed):** Elasticsearch query targeting Sysmon Event 1 process creation events where:
- process.parent.name matches *mshta.exe
- process.name matches *schtasks.exe
- process.command_line contains /Create, /SC ONLOGON, and AppData\Roaming
- Time window: last 30 days
- Expected volume: 0-5 hits in clean environment

**Planned Query Q2 (not executed):** Scheduled task creation logs (Event ID 4698) correlation to capture task XML configuration.

### Pivots
No pivots were executed. Planned pivots included:
- Examine full process tree backward from mshta.exe to identify initial access vector
- Retrieve scheduled task payload file from AppData\Roaming path for hash analysis
- Query scheduled task creation logs (Event ID 4698) for task XML configuration
- Search for subsequent executions of scheduled task payload
- Correlate network connections (Sysmon Event 3) from mshta.exe PID
- Check for same scheduled task name across multiple hosts

## Findings
Hunt was terminated before query execution due to unresolved false-positive concerns identified in RedTeam review. The FP Hunter persona vetoed the hunt based on:

1. **High false-positive risk in enterprise environments:** mshta.exe is legitimately used by IT automation tools (SCCM, Intune, Tanium), third-party installers, and internal deployment scripts. The proposed disprove conditions do not adequately filter these scenarios.

2. **Insufficient baseline data:** No established baseline exists for normal mshta.exe → schtasks.exe event rates across the organization. Without this baseline, the hunt cannot calibrate detection thresholds or distinguish rare malicious activity from routine IT operations.

3. **Lack of temporal constraints:** The hypothesis does not define a tight time window between mshta.exe execution and schtasks.exe spawn. This risks correlating unrelated historical events, particularly in environments with legacy IT automation.

4. **Missing payload validation:** The hypothesis does not require digital signature verification of the HTA file or the scheduled task payload. Legitimate tools are typically vendor-signed; unsigned payloads should escalate investigation priority.

5. **Overlap with red-team exercises:** Authorized security testing frequently uses this exact technique to validate detection coverage, creating operational noise.

The hypothesis remains technically valid as a detection pattern for HTA-delivered persistence. The behavior described (mshta.exe → schtasks.exe → AppData\Roaming persistence) is documented in real-world campaigns and represents a high-fidelity indicator when properly tuned. However, deployment requires additional engineering to suppress false positives.

## Affected Assets
None identified. Query execution was halted before production data analysis.

## Recommended Actions
1. **Establish baseline** (Owner: Detection Engineering, Urgency: Medium): Query 90-day historical data to determine normal rate of mshta.exe spawning schtasks.exe with /Create /SC ONLOGON flags across representative host population. Define 'rare' threshold (e.g., <0.1% of endpoints).

2. **Refine disprove conditions** (Owner: Detection Engineering, Urgency: Medium): Add explicit whitelist for known legitimate tools (SCCM, Intune, Tanium, specific third-party installers) that use this pattern. Cross-reference against Group Policy Preference logs (Event ID 4739) and SCCM deployment records.

3. **Implement payload validation** (Owner: Detection Engineering, Urgency: High): Require digital signature verification of HTA file executed by mshta.exe. Unsigned or unknown-hash payloads escalate to investigation; vendor-signed binaries suppress alert.

4. **Tighten temporal constraint** (Owner: Detection Engineering, Urgency: Medium): Define maximum time window between mshta.exe process creation and schtasks.exe spawn (recommend <5 seconds) to exclude staged persistence scenarios.

5. **Collect required fields** (Owner: Detection Engineering, Urgency: High): Ensure query captures process.command_line (full), process.parent.command_line, host.hostname, user.name, process.pid, process.parent.pid, and @timestamp with sub-second precision.

6. **Pilot on isolated environment** (Owner: Detection Engineering, Urgency: Medium): Run refined query against test network with known-good IT automation scripts to measure false-positive rate before production deployment.

## Alternative Explanations
1. Legitimate internal IT automation script using mshta.exe to deploy scheduled tasks for line-of-business application installation or configuration.

2. Third-party software updater (legacy SMB client, printer driver, endpoint protection agent) employing mshta.exe as deployment mechanism with task creation in user AppData for on-logon execution.

3. Developer workstation running local convenience scripts (PowerShell/HTA combo) to schedule builds or test harnesses, producing identical command-line pattern.

4. Misconfigured Group Policy Preference (GPP) or System Center Configuration Manager (SCCM) package deploying scheduled tasks via mshta.exe, generating same observable without malicious intent.

5. Authorized red-team or penetration testing exercise intentionally mimicking the reported technique to validate detection coverage.

## Detection Rule
No detection rule produced. Hunt was terminated during RedTeam review phase due to unresolved false-positive concerns. The hypothesis requires baseline tuning, refined disprove conditions, and payload validation logic before Sigma rule generation.

## Hunt Metadata
- **Hunt ID:** 0a37cbf6-2170-4df6-9072-776c6046ac73
- **Report ID:** 2123309c-e848-4a1b-9cf1-3e784154388c
- **Behavior:** LOLBin (T1218.005, T1053.005, T1036.004)
- **Total queries:** 0 (execution halted)
- **Total pivots:** 0 (execution halted)
- **RedTeam aggregate score:** 0.595
- **RedTeam veto:** Yes (FP Hunter persona)
- **Hunt outcome:** INCONCLUSIVE - terminated before query execution due to false-positive risk