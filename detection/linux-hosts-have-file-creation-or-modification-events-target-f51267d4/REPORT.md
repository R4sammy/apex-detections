# Threat Hunt: Linux Dynamic Linker Configuration Hijacking (2024-01-09)

## Disposition
INCONCLUSIVE · **Severity:** MED · **Confidence:** 0.45

## Executive Summary
This hunt investigated unauthorized modifications to Linux dynamic linker configuration files (/etc/ld.so.preload, /etc/ld.so.conf.d/) by non-package-manager processes, a high-impact persistence technique (MITRE T1574.006) used by multiple documented Linux rootkits. Two queries were initiated but results were incomplete—query execution appears to have been truncated mid-payload, preventing full analysis of file modification events. The hypothesis is technically sound and addresses a critical persistence vector, but evidence collection was not completed. Re-execution with full result capture is required before final disposition can be determined.

## Source
- **Report:** Elastic Security Labs - Linux Rootkits 2: Caught in the Act
- **URL:** https://www.elastic.co/security-labs/linux-rootkits-2-caught-in-the-act
- **Source tier:** T1 (vendor research lab)
- **Published:** Not specified
- **Triaged hunt-worthy at:** 0.88 value score, 0.91 feasibility score

## Hypothesis
**Linux hosts have file creation or modification events targeting /etc/ld.so.preload or /etc/ld.so.conf.d/ by non-package-manager processes**

This hypothesis targets a well-established Linux persistence mechanism where attackers modify the dynamic linker configuration to achieve system-wide library hijacking. By inserting malicious shared objects into /etc/ld.so.preload or adding paths to /etc/ld.so.conf.d/, adversaries can inject code into every process on the system, establishing durable persistence with broad process injection capability.

## Behavior Tested
- **Kind:** TTP
- **Description:** The dynamic linker configuration was modified by creating or altering files in /etc/ld.so.conf.d/ or /etc/ld.so.preload to achieve persistent, system-wide library hijacking.
- **MITRE ATT&CK:** T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking)
- **Data Sources:** file_create, file_modify
- **Target Paths:** /etc/ld.so.preload, /etc/ld.so.conf, /etc/ld.so.conf.d/*
- **Detection Opportunities:** Monitor for file creation or modification events in /etc/ld.so.conf.d/; alert on any modification to /etc/ld.so.preload file

## Hunt Execution

### Queries

**Query Q1: File modification events on dynamic linker configuration**
- **Tested:** File creation or modification events targeting /etc/ld.so.preload, /etc/ld.so.conf, or /etc/ld.so.conf.d/* within the last 90 days, excluding known package managers (apt, yum, dnf, dpkg, rpm, systemd, update-alternatives, aptitude, zypper, pacman)
- **Result:** Query was submitted but results were not fully returned—payload appears truncated in hunt context. Unable to determine hit count, affected hosts, or event details.
- **Status:** Incomplete

**Query Q2: Follow-up query on /etc/ld.so.preload paths**
- **Tested:** Additional wildcard search on /etc/ld.so.preload* paths
- **Result:** Query was listed in execution plan but results were not captured or query was not fully executed.
- **Status:** Incomplete

### Pivots
No pivots were executed due to incomplete query results. Planned pivots included:
- Examine content of modified files to identify injected shared object paths
- Check for creation of referenced shared object files in /tmp, /dev/shm, or /usr/local/lib
- Investigate process execution history within temporal window of file modification
- Search for other file modifications by same user or process in persistence paths
- Correlate with network connection events for potential C2 communication

## Findings

### Technical Execution Issues
The hunt could not be completed due to incomplete query result capture. Query Q1 was submitted with appropriate filters (excluding known package managers, 90-day lookback, targeting specific file paths) but the results payload was truncated in the hunt context. Query Q2 was listed but not executed or results not returned. This prevents any determination of whether malicious activity occurred.

### RedTeam Review Insights
Despite incomplete execution, RedTeam reviews surfaced important considerations for future runs:

**False Positive Risk (fp_hunter score: 0.3):** Significant FP risk identified from legitimate system administration activities. IT automation tools (Ansible, Puppet, Chef, SaltStack) frequently modify these files as part of approved deployments. System administrators routinely edit /etc/ld.so.preload or /etc/ld.so.conf.d/ using vi, nano, or shell redirects for third-party software requiring custom library paths. These legitimate activities will match the query criteria.

**Temporal Correlation Gap (timing_tester score: 0.5):** The hypothesis lacks tight temporal correlation between file write and malicious payload execution. LD_PRELOAD persistence is often established long before the actual malicious payload is triggered. Without requiring that suspicious parent processes (e.g., shells from network services) be active within 60 seconds of the file modification event, the hunt risks creating false causal links between legitimate SSH sessions and unrelated system events.

**Alternative Explanations (alternative_generator score: 0.45):** Multiple benign scenarios can produce identical telemetry: application instrumentation agents (New Relic, AppDynamics, Dynatrace, Falco) inject LD_PRELOAD hooks via systemd timers; container runtime helpers (Docker, Podman, LXC) modify ld.so configuration for host-library sharing; vendor-supplied installers (database drivers, GPU toolkits) use shell redirection from /tmp to configure library paths.

### Attribution and Source Quality
The hypothesis is behavior-centric, not actor-centric (attribution_skeptic score: 0.92). It describes a well-documented TTP used across multiple threat actors without depending on any specific attribution. The source is Elastic Security Labs research, a T1 vendor research lab with no commercial incentive bias concerns (source_bias_auditor score: 0.8).

## Affected Assets
None identified. Query results incomplete.

## Recommended Actions

1. **Re-execute Query Q1 with full result capture** — Ensure all 50 results are returned and parsed. Verify query execution completed successfully. **Owner:** Hunt Lead. **Urgency:** HIGH.

2. **Apply RedTeam-recommended filters if hits are found** — Exclude Ansible, Puppet, Chef, SaltStack processes. Correlate with CMDB/automation logs. Require known-benign parent process or admin user context. **Owner:** Detection Engineer. **Urgency:** HIGH.

3. **Pivot to file content analysis and process execution history** — If hits remain after filtering, examine file content to identify injected shared object paths. Investigate process execution history within 60-second window of file write (per timing_tester recommendation). **Owner:** Hunt Lead. **Urgency:** HIGH.

4. **Establish allow-list of approved vendor libraries and system administration accounts** — Reduce FP noise in future runs by maintaining a baseline of legitimate modifications. **Owner:** Security Operations. **Urgency:** MED.

5. **Document baseline of normal ld.so.conf.d/ modifications** — Calibrate future alert thresholds by establishing what normal looks like for legitimate tools. **Owner:** Detection Engineer. **Urgency:** MED.

## Alternative Explanations

- **Legitimate system updates or package installations** modifying dynamic linker configuration as part of normal software deployment.
- **IT automation tools** (Ansible, Puppet, Chef, SaltStack) deploying approved library paths for enterprise applications.
- **System administrators** manually editing /etc/ld.so.preload or /etc/ld.so.conf.d/ for third-party software requiring custom library paths.
- **Application instrumentation agents** (New Relic, AppDynamics, Dynatrace, Falco) injecting LD_PRELOAD hooks via systemd timers or init scripts.
- **Container or virtualization host setup scripts** (Docker, Podman, LXC) modifying ld.so configuration to expose container libraries.
- **Vendor-supplied software installers** (database drivers, GPU toolkits, Java runtimes) using shell redirection or file moves from /tmp to configure library paths.

## Detection Rule
No detection rule produced. Reason: Hunt execution incomplete—query results not fully captured. Sigma rule generation requires validated true positive examples or confirmed absence of activity. Re-execution required before rule development can proceed.

## Hunt Metadata
- **Hunt ID:** f51267d4-921d-4cd9-9855-ea4d7fc94be5
- **Total queries:** 2 (incomplete)
- **Total pivots:** 0
- **LLM calls:** Not specified
- **Total cost:** Not specified
- **Duration:** Not specified
- **Disposition rationale:** Query execution truncated mid-payload. Cannot determine presence or absence of malicious activity without complete result set. Hypothesis remains valid but untested.