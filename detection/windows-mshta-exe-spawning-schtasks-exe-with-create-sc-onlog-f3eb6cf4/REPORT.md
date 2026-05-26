# Threat Hunt: mshta.exe spawning schtasks.exe with /Create /SC ONLOGON flags (2026-05-26)

## Disposition
INCONCLUSIVE · **Severity:** MED · **Confidence:** 0.00

## Executive Summary
This hunt targeted a post-exploitation persistence technique where mshta.exe spawns schtasks.exe to create scheduled tasks with /SC ONLOGON triggers pointing to payloads in user AppData directories. Query execution was interrupted before results were returned from the Elasticsearch cluster. No evidence of the targeted behavior was obtained. The hypothesis remains untested and requires re-execution with verified index availability and Sysmon Event 1 logging coverage.

## Source
- **Report:** R4sammy switch validation hunt v3 (fresh image)
- **URL:** https://www.elastic.co/security-labs/r4sammy-fresh-image-2026-05-26
- **Source tier:** demo-switch-detection-repo-v3
- **Published:** 2026-05-26
- **Triaged hunt-worthy at:** 0.86 value score, 0.91 feasibility score

## Hypothesis
Windows mshta.exe spawning schtasks.exe with /Create /SC ONLOGON flags and task payload path in user AppData directories. This hypothesis targets a documented LOLBin abuse pattern (T1218.005) combined with scheduled task persistence (T1053.005) and masquerading (T1036.004). The technique establishes post-exploitation persistence by creating a scheduled task that executes on user logon, with the payload residing in a user-writable directory.

## Behavior Tested
- **Kind:** LOLBin
- **Description:** mshta.exe spawned cmd.exe or powershell.exe which then executed schtasks.exe with /Create /SC ONLOGON flags to establish a scheduled task masquerading as MicrosoftEdgeUpdateCore pointing to update.bat or update.vbs in AppData\Roaming.
- **MITRE ATT&CK TTPs:** T1218.005 (Signed Binary Proxy Execution: Mshta), T1053.005 (Scheduled Task/Job: Scheduled Task), T1036.004 (Masquerading: Masquerade Task or Service)
- **Data Sources:** process_creation, sysmon_event_1, scheduled_task
- **Tradecraft Details:**
  - Parent process: mshta.exe
  - Child process: cmd.exe or powershell.exe → schtasks.exe
  - Command line patterns: schtasks.exe /Create, /TN MicrosoftEdgeUpdateCore, /SC ONLOGON, /TR
  - File paths: C:\Users\<user>\AppData\Roaming\update.bat, C:\Users\<user>\AppData\Roaming\update.vbs
  - Task name masquerades as legitimate Microsoft update service

## Hunt Execution

### Queries

**Q1 — Initial mshta.exe → schtasks.exe chain detection**
- **Target:** winlogbeat-* index, Sysmon Event 1 (process creation)
- **Logic:** Parent process ends with mshta.exe AND child process ends with schtasks.exe AND command line contains /Create, /SC ONLOGON, and AppData\Roaming path substring
- **Time window:** Last 30 days
- **Result:** Query execution incomplete. No hit count, sample matches, or host data returned. Query context shows truncated queries_executed array.

**Q2 — Broader index search for process creation events**
- **Target:** *beat-* indices, multiple event code mappings (event.code:1, event_id:1, winlog.event_id:1)
- **Logic:** Same parent-child and command line filters as Q1, expanded to cover multiple beat agent configurations
- **Result:** Query execution incomplete. No results returned. Hunt context JSON truncated mid-query definition.

### Pivots
No pivots executed. Initial query results required to identify hosts, process trees, and task payloads for further investigation.

## Findings

Query execution was interrupted before results were obtained from the Elasticsearch cluster. The hunt context shows two queries (Q1 and Q2) were defined and submitted but the queries_executed array is truncated. No hit counts, sample event data, or affected host identifiers are present in the supplied context.

Without query results, the following investigative steps could not be performed:
- Identification of hosts where mshta.exe spawned schtasks.exe with the targeted command line pattern
- Analysis of process trees to trace initial access vector (HTA file origin)
- Inspection of scheduled task payload files (update.bat, update.vbs) on disk
- Correlation with network connection events (Sysmon Event 3) from mshta.exe PIDs
- Cross-host analysis to detect campaign spread or lateral movement

The hypothesis remains untested. The behavior may or may not be present in the environment.

## Affected Assets
None identified. Query execution incomplete.

## Recommended Actions

1. **Re-run queries Q1 and Q2** against winlogbeat-* and *beat-* indices to obtain complete result set — Hunt Lead or Detection Engineer, immediate priority
2. **Verify Elasticsearch connectivity and index availability** before retry — Infrastructure/SOC, immediate priority
3. **Confirm Sysmon Event 1 logging coverage** across target environment if indices are unavailable — SOC Lead, high priority
4. **Execute planned pivots** (process tree analysis, payload inspection, network correlation) once results obtained — Hunt Lead, high priority

## Alternative Explanations

- Query syntax error or index mapping mismatch prevented execution
- Elasticsearch cluster unavailable or indices not yet populated with required event data
- Sysmon Event 1 logging not enabled on target hosts, resulting in zero matches
- Time window (last 30 days) contains no instances of the targeted behavior — either environment is clean or behavior does not occur in this organization

## Detection Rule
No detection rule produced. Reason: Hunt execution incomplete; no evidence obtained to validate detection logic or tune false positive filters.

## Hunt Metadata
- **Hunt ID:** f3eb6cf4-beb2-4677-b7ac-9b56faeb80c7
- **Total queries:** 2 (incomplete)
- **Total pivots:** 0
- **LLM calls:** Not available in supplied context
- **Total cost:** Not available in supplied context
- **Duration:** Not available in supplied context