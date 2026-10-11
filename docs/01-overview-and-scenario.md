# 1. Overview & Scenario

## Why this project

Active Directory (AD) is the identity and access backbone of the majority of
organizations. It is also the number-one target of ransomware operators: once an
attacker controls the domain, they control every account, every machine and
every file. For that reason, understanding how AD is attacked — and, more
importantly, how it is defended and monitored — is a core skill for a SOC
analyst.

This lab builds a small but realistic AD environment, then studies it from a
**defender's point of view**. Attacks are only used as a means to an end: to
learn what they look like in the logs and how to stop them.

## The scenario: Clinica San Giorgio

**Clinica San Giorgio** is a fictional outpatient medical clinic with roughly 20
employees across three departments: reception, doctors, and administration. A
single Active Directory domain (`sangiorgio.internal`) manages all user accounts
and access to shared resources.

A healthcare provider is a deliberate choice of scenario:

- **High-value data.** Patient records are among the most sensitive data that
  exist, and are subject to strict data-protection regulation (GDPR, NIS2).
- **A proven ransomware target.** Clinics and hospitals are frequently hit,
  because downtime is life-threatening and the pressure to pay is high.

This makes strong detection and hardening not optional, but mandatory — which is
exactly the mindset the lab is meant to build.

## Threat model

A simple threat model keeps the work focused. The primary threat modelled here is
an **attacker who already has a foothold on the internal network** — for
example, a reception workstation compromised through a phishing email, or a
rogue device plugged into the LAN.

This "assume breach" starting point is realistic: most real-world incidents do
not begin at the Domain Controller, they begin at an ordinary endpoint and move
inward. The attacker's goal is to escalate from that foothold to full control of
the domain. The defender's goal is to **detect the activity early** and make
each step harder.

## Objectives

1. Build a working Active Directory domain on isolated infrastructure.
2. Establish a security logging baseline fit for a SOC.
3. Simulate common AD attack techniques.
4. For each technique, document **what the defender sees** and **how to reduce
   the risk** (hardening + detection).

## Methodology

The lab follows a **purple-team** approach — attack and defense studied together.
Each topic is covered in three steps:

1. **What happens** — the technique at a conceptual level, and why it works.
2. **What the defender sees** — the traces it leaves in the Windows event logs.
3. **How to close / detect it** — the hardening that reduces the risk and the
   detection logic that raises the alarm.

## Scope & ethics

Everything runs inside an **isolated virtual network** with no connection to any
production or home network, and no internet access during the exercises. All
hosts, users, names and data are fictional. The purpose is strictly defensive
learning.
