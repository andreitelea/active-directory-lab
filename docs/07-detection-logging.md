# 7. Detection & Logging

This chapter consolidates the defensive side of the lab: the logging baseline,
the gaps discovered during the attack simulation, and the concrete detection
signatures for each technique. It reflects a SOC analyst's view — what to
collect, and what pattern reveals each attack.

## The logging baseline

Before any attack, an advanced audit policy was deployed domain-wide through a
GPO (`GPO-Audit-Baseline`), enabling the subcategories that matter for AD
attacks:

- **Logon/Logoff** (Success + Failure) — 4624 / 4625
- **Credential Validation** and **Kerberos Authentication/Service Ticket** —
  4768 / 4769 / 4776
- **User Account** and **Security Group Management** — 4720, 4728/4729, …
- **Account Lockout**
- **Process Creation** (Success), with **command line** included in 4688

Reading events is done with `Get-WinEvent -FilterHashtable`, filtered with
`Where-Object` and displayed with `Format-List` (`Format-Table` truncates long
fields).

## Gaps discovered during the simulation

Two blind spots surfaced while attacking — both important lessons:

1. **The audit policy did not reach CLIENT01.** `auditpol` on the workstation
   reported `Process Creation: No Auditing`, so the attacker's remote execution
   (4688) was never recorded locally. **Audit policy must be verified on every
   host, not assumed from the GPO** — workstations are where lateral movement
   lands and are routinely under-logged.
2. **DCSync was invisible by default.** Directory replication is not audited
   unless **Directory Service Access** is explicitly enabled. It had to be
   turned on before event 4662 would record the replication request.

## Event reference

| Event ID | Meaning | Relevance |
|----------|---------|-----------|
| 4624 | Successful logon | Type 3 = network; source IP reveals origin |
| 4625 | Failed logon | Spraying = many accounts failing from one source |
| 4672 | Special privileges assigned | Administrative logon |
| 4688 | Process creation (with command line) | Reveals executed commands (e.g. atexec) |
| 4698 | Scheduled task created | atexec/PsExec-style remote execution |
| 4768 / 4769 | Kerberos TGT / service ticket requested | 4769 with RC4 = Kerberoasting |
| 4728 / 4729 | Member added/removed from a group | Privilege changes |
| 4662 | Operation on a directory object | Replication GUID by a non-DC = DCSync |

## Detection signatures by technique

**Reconnaissance — port scanning.** Effectively invisible in the Security log;
it hides in normal activity. Requires network-level telemetry (firewall logs, an
IDS such as Suricata, or Sysmon network events).

**Reconnaissance — authenticated enumeration.** 4624 Type 3 with
`ANONYMOUS LOGON` from a workstation IP, and users authenticating from hosts
they do not normally use (e.g. `sara.conti` from the attacker's IP rather than
her own workstation).

**Password spraying.** A burst of **4625** failures across many *different*
accounts from a single source IP within the same short window — distinct from
brute force (many failures on one account).

**Kerberoasting.** A **4769** service-ticket request with **RC4 encryption
(`0x17` / `23`)** for a user service account. In an AES-only environment, RC4
requests are themselves anomalous.

**Lateral movement.** 4624 Type 3 + 4672 (administrative network logon) from an
unexpected source, especially a **service account authenticating to a
workstation**; plus 4698 (scheduled task) or service-creation artifacts from the
remote-execution method.

**LSASS credential theft.** Endpoint/EDR detection — Defender flagged the
`comsvcs.dll` MiniDump technique and blocked it. Visible in the Microsoft
Defender operational log and via `Get-MpThreatDetection`.

**DCSync.** A **4662** event referencing the replication right
`DS-Replication-Get-Changes-All` (GUID `1131f6ad-…`) performed by any principal
that is **not a Domain Controller**. High-confidence malicious.

## Recommendations

- **Deploy and verify** the audit policy on every host (`gpupdate /force` +
  `auditpol /get`), including workstations.
- **Enable Directory Service Access auditing** on Domain Controllers so DCSync
  is visible.
- **Centralise logs** into a SIEM for correlation across hosts and for the
  volume-based signatures (spray bursts, abnormal source IPs).
- **Add network and process telemetry** (Sysmon, an IDS) to cover what the
  Security log cannot — notably reconnaissance.
- **Write alerts** for the high-confidence signatures above: RC4 Kerberos
  tickets, non-DC replication, anonymous logons from workstations, and
  credential-dumping detections.
