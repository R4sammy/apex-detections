# Threat Hunt: Linux insmod/modprobe/kmod loading .ko modules from non-standard paths (2025-01-XX)

## Disposition
INCONCLUSIVE · **Severity:** MED · **Confidence:** 0.45

## Executive Summary
A threat hunt for Linux kernel module loading from non-standard paths (insmod/modprobe/kmod with .ko files from /tmp, /dev/shm, /var/tmp, /home) was executed across the environment. The query executed successfully but returned no matches, indicating either the technique is not present in the current dataset or legitimate activity is being filtered correctly. RedTeam review identified significant false-positive risks from legitimate driver installations, development workflows, and package manager staging activities. Without positive evidence, the hunt cannot confirm or rule out the presence of this rootkit loading technique.

## Source
- **Report:** Linux Rootkits 2: Caught in the Act
- **URL:** https://www.elastic.co/security-labs/linux-rootkits-2-caught-in-the-act
- **Source tier:** T1 (Elastic Security Labs)
- **Published:** 2024
- **Triaged hunt-worthy at:** 0.82 value score, 0.88 feasibility score

## Hypothesis
Linux insmod/modprobe/kmod loading .ko modules from non-standard paths.

This hypothesis targets a kernel-space rootkit loading technique where attackers use built-in Linux utilities (insmod, modprobe, kmod) to load malicious Loadable Kernel Modules (LKMs) from attacker-writable or ephemeral paths rather than standard system directories. Kernel-space compromise enables complete system control, process hiding, and defense evasion.

## Behavior Tested
- **Kind:** LOLBin (Living-Off-The-Land Binary)
- **Description:** A malicious Loadable Kernel Module (LKM) was loaded using the built-in insmod or modprobe utilities.
- **MITRE ATT&CK TTPs:** T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions)
- **Data Sources:** process_creation, sysmon_event_1, auditd
- **Tradecraft:**
  - Parent process: bash, sh, or unknown shell
  - Child process: insmod, modprobe, kmod
  - Command-line patterns: `insmod *.ko`, `modprobe -i *.ko`, `kmod insmod *.ko`
  - File paths: /tmp, /dev/shm, /var/tmp, /home, /root (excluding /lib/modules/, /usr/lib/modules/)
- **Detection Opportunities:** Alert on execution of insmod/modprobe/kmod with a .ko file from unusual paths; monitor for kmod process execution with 'insmod' as an argument.

## Hunt Execution

### Queries
- **Q1 (es_query):** Searched all indices for process execution events where process.name matched insmod, modprobe, or kmod AND process.command_line contained `.ko` AND command-line contained one of `/tmp/`, `/dev/shm/`, `/var/tmp/`, `/home/`, `/root/` while excluding `/lib/modules/` and `/usr/lib/modules/`.
  - **Result:** 0 hits. No process execution events matched the signature of kernel module loading from non-standard paths.
  - **Interpretation:** Either the technique is not present in the current environment, or legitimate activity is being correctly filtered by the exclusion logic.

### Pivots
No pivots were executed due to zero initial query hits. Planned pivots included:
- Parent process tree analysis to determine if insmod/modprobe was spawned by a shell session or automated script
- File creation event correlation within 5 minutes prior to module loading
- Kernel log (dmesg, journalctl -k) inspection for 'loading out-of-tree module taints kernel' or 'module verification failed' messages
- Network connection correlation within 10 minutes following module load
- Persistence mechanism checks (modifications to /etc/modules, /etc/modules-load.d/, /etc/modprobe.d/, udev rules)

## Findings
The hunt returned no positive evidence of malicious kernel module loading from non-standard paths. Query Q1 executed successfully against the full dataset with appropriate filters but produced zero matches.

This INCONCLUSIVE result has three possible interpretations:

1. **True Negative:** The technique is not present in the environment. No attacker has loaded a rootkit via insmod/modprobe/kmod from attacker-writable paths during the lookback period.

2. **Data Coverage Gap:** Process creation events with full command-line capture may not be collected from all Linux hosts, or the lookback period may not extend far enough to capture historical activity.

3. **Filter Over-Suppression:** The exclusion logic (filtering out /lib/modules/ and /usr/lib/modules/) may be inadvertently suppressing legitimate staging activity that should be baselined before being excluded.

RedTeam review (aggregate score 0.60) identified significant methodological concerns:

- **FP Hunter (0.5):** Flagged high false-positive risk from legitimate out-of-tree driver installations (NVIDIA, VMware tools) that stage .ko files in /tmp during setup, security research/red team exercises using rootkit PoCs, and developer workstations compiling custom modules.

- **Source Bias Auditor (0.6):** Noted the hypothesis defines 'non-standard paths' with an attacker-centric view that may over-classify legitimate package manager and driver installation activity. The list of suspicious paths (/tmp, /dev/shm, /var/tmp) is narrow and may reflect vendor threat intelligence bias rather than ground-truth platform behavior.

- **Timing Tester (0.5):** Identified loose correlation windows (5-minute file creation pivot, ±2-minute kernel log pivot) that could miss tight causal chains or conflate unrelated system activity.

- **Alternative Generator (0.5):** Documented five plausible legitimate explanations for the behavior, including package manager post-install scripts, udev hardware hot-plug services, kernel development workflows, container orchestration module staging, and security-orchestration tool activity.

- **Evidence Gap (0.6):** Noted the hypothesis lacks specificity on required process execution fields and assumes availability of kernel logs without confirming they are collected and indexed.

The Attribution Skeptic (0.92) confirmed the hypothesis is appropriately behavior-based and contains no weak actor attribution.

## Affected Assets
None identified.

## Recommended Actions
1. **Refine query filters to reduce false positives:** (1) Exclude parent processes matching known package managers (apt, dnf, yum, dpkg) and hardware installer scripts (nvidia-installer, vboxadd-install); (2) Require parent process context (bash/sh spawned by user, not system service); (3) Add file signature validation to exclude signed vendor modules — **owner: Detection Engineering, urgency: Medium**

2. **Broaden hunt scope to capture legitimate staging activity:** Re-run query with logging of all insmod/modprobe/kmod executions (including /lib/modules/ paths) for 7 days to establish baseline of legitimate kernel module loading patterns in the environment — **owner: SOC/Hunt Lead, urgency: Medium**

3. **Implement kernel log correlation:** Verify that dmesg/journalctl kernel logs are being collected and indexed; if available, add pivot to correlate 'module verification failed' or 'loading out-of-tree module taints kernel' messages within ±90 seconds of process execution — **owner: Logging/SIEM, urgency: Low**

4. **Validate data source completeness:** Confirm that process creation events with full command-line capture are being collected from all Linux hosts (Sysmon Event 1, auditd, or EDR agent); if coverage gaps exist, prioritize endpoints for agent deployment — **owner: Endpoint Security, urgency: Medium**

## Alternative Explanations
- Legitimate out-of-tree kernel module installation (NVIDIA drivers, VMware tools, VirtualBox Guest Additions) stages .ko files in /tmp or /var/tmp during setup before moving to /lib/modules/
- Package manager post-install scripts (apt, dnf, yum) unpack and load kernel modules from temporary staging directories during kernel updates or driver package installation
- Kernel development or debugging workflows on developer workstations compile and load custom .ko files from /tmp, /var/tmp, or user home directories for testing
- Automated hardware hot-plug services (udev, systemd-modules-load) copy newly discovered driver modules to runtime directories (/run/udev/modules/, /run/modprobe.d/) and invoke insmod from those locations
- Container or virtualization orchestration (Docker, LXC, KVM) loads kernel modules from host-mounted bind paths (e.g., /var/lib/docker/tmp) to provide device access inside containers
- Security-orchestration tools (SELinux policy loaders, AppArmor profile updaters, kernel-hardening CI/CD pipelines) stage signed policy or hardening modules in user-writable areas before loading

## Detection Rule
No detection rule produced. Reason: Zero positive findings during hunt execution. A Sigma rule cannot be validated without sample data. Recommend re-running hunt after implementing data source validation and baseline establishment (see Recommended Actions 2 and 4).

## Hunt Metadata
- **Hunt ID:** 81d94bca-dc2d-4b3f-8b38-b421ade73e69
- **Total queries:** 1
- **Total pivots:** 0
- **LLM calls:** (metadata not provided)
- **Total cost:** (metadata not provided)
- **Duration:** (metadata not provided)