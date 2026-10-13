# 6. Hardening

The attack simulation in [chapter 5](05-attack-techniques.md) only worked
because of specific weaknesses, most of them deliberately left in place. This
chapter collects the countermeasures, each tied to the attack it defeats. They
are grouped by theme and roughly ordered by impact.

## Credential hygiene

| Weakness (seen in the lab) | Hardening |
|----------------------------|-----------|
| Same temporary password for every new user | Unique initial passwords, forced change at first logon (already applied), and a strong password policy (length ≥ 14) |
| Weak, guessable user passwords (enabled spraying) | Passphrase guidance, ban common/breached passwords (Azure AD Password Protection or an equivalent banned-list) |
| Weak, never-expiring service account password (enabled Kerberoasting) | **gMSA** (group Managed Service Accounts): 120-character random passwords rotated automatically by AD |
| Shared local administrator password across machines (enabled pass-the-hash) | **LAPS**: a unique, random local admin password per machine |

Password spraying and Kerberoasting both ultimately rely on humans or admins
choosing weak passwords; credential quality is the single highest-impact
control.

## Privilege and administrative tiering

- **Least privilege for service accounts.** `svc-gestionale` was a local
  administrator on CLIENT01 — that single misconfiguration handed the attacker
  SYSTEM. Service accounts should hold only the rights their application needs,
  and never be local admins unless strictly required.
- **Tiered administration.** A Domain Admin logging on to a workstation left its
  credentials in that machine's memory — the root cause of the escalation path.
  Tier-0 accounts (Domain Admins) must only authenticate to Tier-0 systems
  (DCs), never to workstations.
- **Minimise Domain Admins.** Keep the group as small as possible; use delegated,
  task-specific accounts for routine administration.
- **Separate admin accounts** (already applied: `adm.andre` is distinct from a
  normal user account).

## Kerberos hardening

- **Enforce AES, disable RC4.** Kerberoasting is practical because the service
  ticket was encrypted with RC4. Requiring AES encryption for tickets removes
  the fast offline-cracking path.
- **gMSA** (above) makes any roasted ticket effectively uncrackable.

## Network and attack surface

- **Keep the workstation firewall closed.** CLIENT01's default firewall blocked
  inbound SMB and stopped lateral movement until it was opened. Remote
  management should be scoped narrowly (specific admin hosts), not opened
  broadly.
- **SMB signing** (already enforced: `signing:True`) blocks NTLM relay.
- **SMBv1 disabled** (already the case).
- **`ms-DS-MachineAccountQuota = 0`** stops ordinary users from joining rogue
  computers to the domain (default is 10).
- **Server Core for Domain Controllers** reduces the DC's attack surface versus
  the Desktop Experience used here for learning.
- **Restrict anonymous enumeration** (already good on Server 2022).

## Endpoint protection

- **Keep EDR/Defender enabled.** Defender blocking the LSASS dump is what broke
  the attack chain — this is not optional.
- **Credential Guard** isolates secrets from LSASS using virtualization.
- **LSASS protection (RunAsPPL)** makes memory dumping far harder.
- **Attack Surface Reduction (ASR) rules**, in particular "Block credential
  stealing from lsass.exe".

## Resilience

- **Deploy a second Domain Controller.** The lab has a single DC — a single
  point of failure for the entire domain.

## Attack → countermeasure summary

| Attack | Primary countermeasure |
|--------|------------------------|
| Reconnaissance (port scan) | Network monitoring (detection, not prevention) |
| Authenticated enumeration | Least privilege; accept that any credential reads the directory |
| Password spraying | Strong passwords, banned-password lists, lockout/throttling |
| Kerberoasting | gMSA, AES-only Kerberos |
| Lateral movement (SMB exec) | Least privilege for service accounts, scoped firewall, LAPS |
| LSASS credential theft | Defender/EDR, Credential Guard, RunAsPPL |
| DCSync escalation | Protect Tier-0 credentials, tiered admin, DS-access auditing |
