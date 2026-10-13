# 5. Attack Techniques Simulation

With the domain built and logging in place, the lab now shifts to its main
purpose: running common Active Directory attack techniques from the Kali host
and studying them **from the defender's side**. Every technique is presented in
three parts:

1. **Attack** — what the attacker does, and why.
2. **Detection** — what (if anything) the defender sees in the logs.
3. **Takeaways** — what this teaches about hardening and monitoring.

All traffic originates from **KALI01 (10.10.10.100)** against **DC01
(10.10.10.10)** and **CLIENT01 (10.10.10.20)**, inside the isolated lab network.

> The attacker in this chapter starts as an unauthenticated outsider who has
> only gained a foothold on the network (the *assume breach* model from
> [chapter 1](01-overview-and-scenario.md)). No credentials are known at the
> outset.

---

## 5.1 Reconnaissance

Reconnaissance is the first move after gaining a foothold: mapping the network
and the domain before choosing a target. The goal of this section is to show how
much an attacker can learn with no credentials, and at what point that activity
starts leaving traces.

### Host discovery

The attacker first finds which machines are alive on the subnet. A normal
`ping` is unreliable here because the Windows Firewall drops ICMP by default — so
the Windows hosts appear "down". On a local network, `nmap` instead uses **ARP**,
a lower-layer request ("who has this IP?") that a host on the same subnet must
answer for the network to function at all. The firewall cannot hide a machine
from ARP.

```bash
sudo nmap -sn 10.10.10.0/24
```

- `-sn` — ping scan only: discover live hosts, do not scan ports (the quietest
  form of discovery).

![nmap -sn discovering the three lab hosts via ARP](../images/05-01-nmap-host-discovery.png)

All three hosts are found. DC01 and CLIENT01 are reported with a **MAC address
(Microsoft)** — proof they were discovered via ARP, not ping. **Lesson:** a
host-based firewall does not conceal a machine from an attacker already on the
local network.

### Port scanning the Domain Controller

Next, the attacker inspects which services DC01 exposes. Open ports fingerprint
the machine's role.

```bash
sudo nmap -sV -p- 10.10.10.10
```

- `-sV` — identify the service and version behind each open port.
- `-p-` — scan all 65,535 TCP ports, not just the common ones.

![nmap service scan of DC01 showing the full set of Active Directory ports](../images/05-02-nmap-dc-portscan.png)

The open ports are an unmistakable Domain Controller signature:

| Port(s) | Service | Meaning |
|---------|---------|---------|
| 53 | DNS | Name resolution |
| 88, 464 | Kerberos, kpasswd | Domain authentication |
| 389, 636 | LDAP, LDAPS | The directory ("address book") |
| 3268, 3269 | Global Catalog | Forest-wide directory — confirms the DC role |
| 445, 139, 135 | SMB, NetBIOS, RPC | File sharing and remote procedure calls |
| 5985 | WinRM | PowerShell remoting |
| 9389 | AD Web Services | Backend for the `ActiveDirectory` PowerShell module |
| 49664+ | RPC dynamic range | High ephemeral RPC ports |

Without any credentials, `nmap` already reports `Host: DC01` and, from the LDAP
service, `Domain: sangiorgio.internal`.

**Detection — and a critical gap.** With the audit policy
configured as the logging baseline (covered in the detection chapter), this full port scan
produced **no distinctive events** in the Windows Security log. Grouping the
Security events of that period by Event ID returned only the normal background
of a running DC (logons, logoffs, key operations) — nothing that identifies a
scan. The scan is not merely unlogged; it is **buried in normal activity**.
Catching network reconnaissance requires network-level telemetry (firewall
logging, an IDS such as Suricata, or Sysmon network events), not the default
Security log.

### Probing SMB anonymously

The attacker now queries the SMB service directly, as an anonymous (null)
session, to fingerprint the host and its security posture.

```bash
nxc smb 10.10.10.10
```

`netexec` (`nxc`) is the industry-standard tool for this — the successor to
CrackMapExec.

![netexec SMB probe of DC01 as an anonymous session](../images/05-03-nxc-smb-info.png)

```
SMB  10.10.10.10  445  DC01  Windows Server 2022 Build 20348 x64
     (name:DC01) (domain:sangiorgio.internal) (signing:True) (SMBv1:None) (Null Auth:True)
```

- **`signing:True`** — SMB signing is required. Each message carries a signature
  the receiver verifies, which blocks **NTLM relay** attacks (an attacker
  capturing a user's authentication and replaying it to the DC). This is a good
  posture and one of the first things a pentester checks.
- **`SMBv1:None`** — the legacy, WannaCry-era protocol is disabled.
- **`Null Auth:True`** — the DC accepted the anonymous connection. The door is
  ajar; the question is what fits through it.

### Enumerating users: anonymous vs authenticated

The real prize in reconnaissance is the list of usernames — half of a
password attack (the other half is the password). First, as an anonymous user:

```bash
nxc smb 10.10.10.10 -u '' -p '' --users
```

![Anonymous user enumeration returns an empty list](../images/05-04-nxc-users-anonymous.png)

The anonymous session connects (`[+]`), but the user list comes back **empty**.
Windows Server 2022 restricts anonymous enumeration of domain accounts by
default — on legacy versions (2003/2008) the same request returned every name.
This default protection works.

Now the same request, authenticated as **`sara.conti`** — a reception account
with no special privileges:

```bash
nxc smb 10.10.10.10 -u 'sara.conti' -p '<password>' --users
```

![Authenticated enumeration as sara.conti returns all 9 domain users](../images/05-05-nxc-users-authenticated.png)

The empty list becomes the **full directory**: all 9 accounts, including the
system accounts `Administrator`, `Guest` and `krbtgt`, the real users, and the
administrative account **`adm.andre`**.

This is the central Active Directory lesson: the barrier is not "anonymous vs
everything", it is **no credential vs any credential**. Any authenticated user
can read almost the entire directory — this is by design, because the directory
must be readable for the domain to function. Three details an attacker now has:

- **`adm.andre` is visible.** Starting from a receptionist, the attacker now
  knows exactly which account to target for privilege — the admin naming
  convention (`adm.*`) is predictable.
- **`krbtgt`** (described as "Key Distribution Center Service Account") signs
  every Kerberos ticket in the domain — the target of a future *Golden Ticket*.
- **`BadPW` (bad password count)** and **`Last PW Set`** help an attacker spray
  passwords without tripping account lockout.

A single stolen password — even a receptionist's — turns the blank page into the
company directory.

### Detection: authentication leaves a trace

Port scanning was silent, but enumeration required **authentication**, and
authentication is logged (the Tema 0 baseline). On DC01:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddMinutes(-25)} |
  Where-Object { $_.Message -match '10\.10\.10\.100' } |
  Select-Object TimeCreated,
    @{N='User';      E={$_.Properties[5].Value}},
    @{N='LogonType';  E={$_.Properties[8].Value}},
    @{N='SourceIP';   E={$_.Properties[18].Value}} |
  Format-Table -AutoSize
```

- Event **4624** = successful logon; `LogonType 3` = network logon.
- The `Where-Object` filter keeps only logons originating from Kali.

![DC Security log showing network logons from 10.10.10.100](../images/05-06-dc-logon-events.png)

The log reconstructs the whole reconnaissance timeline from a single IP:

```
16:46  ANONYMOUS LOGON   from 10.10.10.100   (nxc smb probe)
16:49  ANONYMOUS LOGON   from 10.10.10.100   (anonymous user enumeration)
16:53  sara.conti        from 10.10.10.100   (authenticated enumeration)
```

Two findings a SOC analyst would act on:

- **`ANONYMOUS LOGON` network logons from a workstation IP** — legitimate users
  do not routinely produce these.
- **`sara.conti` authenticating from `10.10.10.100`** — but her workstation is
  `10.10.10.20`. A reception account signing in from the Kali host is the
  behavioral anomaly that triggers an investigation.

Windows does not log "someone read the user list" (that needs directory-service
auditing, not enabled here); it logs the **network logon** that made the read
possible. The defender does not see the *looking* — they see the *entering*.

### Takeaways

- A host firewall does not hide machines from an attacker on the same subnet
  (ARP discovery).
- **Port scanning is effectively invisible** to the default Security log —
  network-level monitoring is required to detect it.
- Anonymous enumeration is restricted by default on Server 2022 (good), but
  **any single valid credential exposes the entire directory** — which is why
  least privilege and credential protection are the heart of AD defense.
- Predictable admin account names (`adm.*`) hand the attacker their next target
  for free.
- Authenticated reconnaissance is detectable through **behavioral** signals:
  anonymous network logons, and users authenticating from unexpected hosts.
