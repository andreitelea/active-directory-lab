# 8. Lessons Learned

## The kill chain, end to end

Starting as an unauthenticated outsider with only a foothold on the network, the
simulation followed a realistic path:

1. **Reconnaissance** — mapped the network via ARP, fingerprinted the DC, and
   enumerated every domain user with a single low-privilege credential.
2. **Credential access** — password spraying caught a weak password;
   Kerberoasting cracked a service account offline.
3. **Lateral movement** — a service account that was local admin on CLIENT01
   gave SYSTEM on that machine and a harvest of local hashes.
4. **Privilege escalation** — the attempt to steal the Domain Admin's cached
   credentials was **blocked by Windows Defender**, breaking the chain. The
   final DCSync step was studied separately, for detection only.

Each step was paired with what the defender could see — the core purpose of the
project.

## What held, and what failed

**Defences that worked:**

- Server 2022's default restriction on anonymous enumeration
- SMB signing (blocks NTLM relay)
- The workstation host firewall (blocked SMB lateral movement by default)
- **Windows Defender** (blocked the LSASS credential dump — the decisive moment)

**Misconfigurations that enabled the attack:**

- A shared, weak temporary password across users
- A service account with a weak password and local admin rights on a workstation
- A Domain Admin logging on to a workstation (credentials left in memory)
- An audit policy that never reached the workstation, and replication auditing
  left off by default

The pattern is consistent: the attacker advanced through **configuration and
credential mistakes**, and was stopped by a **modern endpoint control**. Defence
in depth matters precisely because no single layer catches everything.

## Key takeaways

- In Active Directory, the real boundary is **no credential vs. any credential**:
  a single account reads almost the entire directory, so credential protection
  and least privilege are central.
- The most dangerous attacks (Kerberoasting, DCSync) **abuse legitimate
  features**, so prevention depends on configuration (AES, tiering, gMSA) and
  detection depends on deliberately enabling the right auditing.
- Workstations are the soft landing zone for lateral movement and are routinely
  under-logged — they deserve the same audit rigour as servers.
- Detection must be **planned in advance**: DCSync and reconnaissance were blind
  spots until the right telemetry was turned on.

## Skills demonstrated

- Active Directory design, administration and troubleshooting (PowerShell-first)
- Offensive tradecraft for defensive understanding: `nmap`, `netexec`,
  Kerberoasting, pass-the-hash concepts, DCSync
- Windows security logging and Event Log analysis, with concrete detection
  signatures
- Blue/purple-team methodology: attack → detect → harden

## Responsible teardown

Because the simulation exposed real secrets inside the lab, the environment is
reset before decommissioning:

- Reset the **`krbtgt`** password **twice** (invalidates any forged Golden
  tickets).
- Reset the passwords of **`adm.andre`** and **`svc-gestionale`**, and remove
  `svc-gestionale` from CLIENT01's local Administrators group.
- Revert the deliberately weak passwords, or delete the lab accounts.
- Finally, delete the lab VMs and virtual switch.

The lab is isolated throughout (a private virtual network with no route to any
production or home network), and all hosts, users and data are fictional.
