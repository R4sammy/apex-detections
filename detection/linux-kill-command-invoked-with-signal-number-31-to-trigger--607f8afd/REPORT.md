# Threat Hunt: Linux kill command invoked with signal number >31 to trigger rootkit covert control channel (2024-01-15)

## Disposition
INCONCLUSIVE · **Severity:** MED · **Confidence:** 0.35

## Executive Summary
This hunt investigated whether Linux systems in the environment were using high-numbered kill signals (>31) as covert control channels for kernel rootkits, a technique documented in rootkits like Diamorphine. Query execution was incomplete due to data availability constraints, and no confirmed detections were produced. The RedTeam review identified critical concerns: the FP Hunter persona issued a veto citing high false-positive risk from legitimate enterprise applications, red-team exercises, and system administration scripts. Without environmental baseline metrics for legitimate high-numbered signal usage and insufficient corroborating evidence (kernel module loads, taint messages, process tree anomalies), the hunt cannot distinguish malicious activity from benign custom inter-process communication. Recommend establishing baseline signal usage patterns before operationalizing this detection.

## Source
- **Report:** Linux Rootkits 2: Caught in the Act
- **URL:** https://www.elastic.co/security-labs/linux-rootkits-2-caught-in-the-act
- **Source tier:** T1 (Elastic Security Labs)
- **Published:** 2023
- **Triaged hunt-worthy at:** 0.88 value score, 0.91 feasibility score

## Hypothesis
**Linux kill command invoked with signal number >31 to trigger rootkit covert control channel**

Rootkits like Diamorphine use high-numbered signals (beyond the 31 standard POSIX signals) as covert triggers to activate hidden functions such as privilege escalation, process hiding, or module unloading. This hypothesis tests whether the kill command or direct kill() syscalls are being invoked with signal numbers >31, which have near-zero legitimate use via the kill command in standard system operations.

## Behavior Tested
- **Kind:** LOLBin (Living Off the Land Binary)
- **Description:** A high-numbered, non-standard signal was sent via the kill command to trigger a hidden function within a rootkit.
- **MITRE ATT&CK TTPs:** T1055 (Process Injection)
- **Data Sources:** process_creation, auditd
- **Tradecraft:**
  - **Child Process:** kill
  - **Command-Line Patterns:** `kill -64 <pid>`, `kill -32 <pid>`, or any signal number >31
- **Detection Opportunities:**
  - Monitor for kill command executions with signal numbers greater than 31
  - Use auditd to log all kill syscalls and alert when the signal argument (a1) is in the unassigned range (e.g., 64 for Diamorphine)

## Hunt Execution

### Queries

**Query Q1 (process.command_line pattern matching):**
- **Tested:** Process creation events where command_line contains kill command with signal numbers 32-999
- **Query Logic:** Wildcard and regex patterns matching `kill -32` through `kill -999`, including `-s` flag variants
- **Time Window:** Last 90 days
- **Result:** Query executed but results incomplete due to index availability constraints. No confirmed hits in available telemetry.

**Query Q2 (auditd syscall logging):**
- **Tested:** Auditd syscall='kill' events where signal argument (a1 in hex) converts to decimal >31
- **Query Logic:** Filtered audit logs for kill syscalls with high-numbered signal arguments
- **Time Window:** Last 90 days
- **Result:** Query could not complete; audit logs not uniformly indexed across monitored hosts. Insufficient data to produce results.

### Pivots
No pivots were executed due to absence of initial query hits. Planned pivots included:
- Identify target PID receiving high-numbered signal and correlate with process tree
- Check for kernel module loading events (init_module/finit_module) within ±5 minutes
- Search for kernel taint messages in /var/log/kern.log or dmesg
- Examine file creation in /dev/shm, /tmp, or hidden directories within prior 24 hours
- Correlate with network connections from processes masquerading as kernel threads

## Findings

This hunt produced no confirmed detections. The absence of findings is attributable to three factors:

1. **Data Availability Constraints:** Query Q1 executed against process creation logs but encountered incomplete index coverage. Query Q2 targeting auditd syscall logs could not complete due to non-uniform audit log collection across monitored Linux hosts. Without comprehensive syscall-level telemetry, the hunt cannot reliably detect direct kill() invocations that bypass command-line logging.

2. **RedTeam Veto on False Positive Risk:** The FP Hunter persona issued a veto (score 0.2) identifying three high-probability false-positive sources:
   - Custom inter-process communication frameworks in legacy enterprise applications that utilize high-numbered signals for internal signaling
   - Red-team or penetration testing exercises that frequently invoke kill with high-numbered signals to test rootkit detection capabilities
   - Misconfigured or experimental system administration scripts using non-standard signals without malicious intent

   The hypothesis lacks environmental context to distinguish these benign uses from malicious rootkit triggers.

3. **Lack of Corroborating Evidence:** The hypothesis relies on pivots to kernel module loading, taint messages, and process tree anomalies to validate findings. No such corroborating signals were available in the collected telemetry. Single-signal detections (kill command alone) are insufficient to confirm rootkit activity without additional context.

Additional RedTeam concerns:
- **Attribution Skeptic (score 0.75):** Noted the hypothesis conflates technique with actor. High-numbered signals are used by multiple rootkit families (Reptile, Suterusu) and legitimate applications, not unique to Diamorphine. The hypothesis tests a behavior, not an actor.
- **Source Bias Auditor (score 0.4):** Flagged vendor incentive bias. The hypothesis is derived from security vendor reports with commercial interest in rootkit detections, lacking multi-source incident confirmation of real-world prevalence.
- **Timing Tester (score 0.4):** Identified the ±5 minute correlation window for kernel module loading as too loose; legitimate system events could create false causal links.
- **Alternative Generator (score 0.45):** Provided five alternative explanations for high-numbered signal usage, all benign, reinforcing the need for environmental baseline.
- **Evidence Gap (score 0.6):** Noted missing required fields (uid/gid, parent process details) and unverified data source availability (init_module/finit_module syscall logs, /var/log/kern.log indexing).

## Affected Assets
None identified.

## Recommended Actions

1. **Establish baseline:** Measure legitimate high-numbered signal usage (SIGRTMIN-SIGRTMAX, 34-64) in your environment over 30 days to identify known applications and services that use real-time signals. Document signal-to-application mappings and create a whitelist. *Owner: Security Engineering. Urgency: Medium (complete within 30 days).*

2. **Refine hypothesis:** Rephrase to remove tool-specific attribution (Diamorphine) and focus on behavior: 'Non-standard signal usage (>31) via kill command without corresponding legitimate application context.' This reduces false positives and improves signal-to-noise ratio. *Owner: Threat Hunt Lead. Urgency: Low (before next hunt iteration).*

3. **Implement corroborating pivots:** Before alerting on high-numbered kill signals, require correlation with at least one of: (a) unsigned kernel module load within ±10 seconds, (b) kernel taint message, or (c) process masquerading as kernel thread (kworker, kthreadd). Single-signal detections will generate excessive noise. *Owner: Detection Engineering. Urgency: Medium (before operationalizing detection).*

4. **Audit red-team and security testing schedules:** Correlate any high-numbered kill signals with authorized penetration testing exercises and security research activities. Suppress alerts matching documented test windows. *Owner: Red Team / Security Operations. Urgency: Low (ongoing coordination).*

5. **Verify data sources:** Confirm that auditd syscall logging (init_module, finit_module, kill) is enabled and indexed on all monitored Linux hosts. Current query execution revealed incomplete audit log coverage. *Owner: Security Engineering / Platform Team. Urgency: High (prerequisite for future hunts).*

6. **Re-evaluate after baseline:** Once baseline is established and corroborating signals are in place, re-run this hunt with refined query logic. Current evidence is insufficient to operationalize detection. *Owner: Threat Hunt Lead. Urgency: Low (after baseline complete).*

## Alternative Explanations

- Legitimate enterprise applications or custom in-house services using POSIX real-time signals (SIGRTMIN-SIGRTMAX, 34-64) for inter-process communication, config reloads, or buffer flushes — common in high-performance data pipelines and telemetry agents.
- System orchestrators (systemd, Kubernetes, Docker) or administration scripts invoking high-numbered signals as graceful shutdown/reload hooks for containerized services with registered custom signal handlers.
- Security-oriented tools (SELinux policy reloaders, AppArmor profile updaters, intrusion-detection agents) using real-time signals to trigger kernel policy reloads without service interruption.
- Authorized red-team or internal penetration-testing exercises deliberately using non-standard signals to simulate rootkit-style control channels; these exercises are frequent in mature environments and will dominate signal-noise ratio.
- Kernel or driver debugging utilities (kdump, crash, dynamic tracing frameworks) sending high-numbered signals to provoke controlled panics or synchronize with kernel modules during testing on production hosts.
- Misconfigured or experimental system administration scripts using non-standard signals without malicious intent during troubleshooting or configuration testing.

## Detection Rule
No detection rule produced. Reason: Hunt produced no confirmed detections and RedTeam review identified critical false-positive risks requiring environmental baseline and refined correlation logic before operationalization.

## Hunt Metadata
- **Hunt ID:** 607f8afd-0747-4a14-965f-88cf3a28e6cf
- **Total queries:** 2
- **Total pivots:** 0
- **LLM calls:** 8 (hypothesis generation, query generation, RedTeam reviews)
- **Total cost:** $2.47
- **Duration:** 4 min 12 sec