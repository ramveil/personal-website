---
title: "Privilege Escalation and Credential Abuse in a Startup Active Directory Environment"
description: "Gradient Resources & Tools"
publishDate: 2026-03-01
tags:
  - "Windows Exploitation"
  - "Privilege Escalation"
  - "Evil-WinRM"
  - "Active Directory"
  - "Kerbrute"
image: "/assets/works/privesc.png"
order: 1
isShow: true
---

## 📌 Project Overview
⚠️ For full scripts and explanation, you can visit my github: https://github.com/ramveil/Privilege-Escalation-and-Credential-Abuse-in-a-Startup-Active-Directory-Environment

This project simulates a realistic internal penetration test against a small startup infrastructure built on **Microsoft Active Directory**. The primary objective is to demonstrate a full attack chain starting from zero knowledge and zero credentials to achieving full domain compromise by exploiting configuration weaknesses rather than software vulnerabilities.

## 🏗️ Lab Infrastructure
The environment was designed to mimic a standard corporate network within a private internal subnet (`192.168.56.0/24`).

### Network Topology & Host Details
| Hostname | Operating System | IP Address | Roles & Key Services | Specifications |
| :--- | :--- | :--- | :--- | :--- |
| **Attacker** | Kali Linux | `192.168.56.128` | Penetration Testing Arsenal | 2 CPU, 4GB RAM, 80GB Disk |
| **DC01** | Windows Server 2022 | `192.168.56.10` | Domain Controller (`startup.local`) | 2 CPU, 4GB RAM, 60GB Disk |
| **Workstation**| Windows 10 Pro | `192.168.56.20` | Domain-Joined Client | 2 CPU, 4GB RAM, 60GB Disk |

---

## 🛠️ Penetration Testing Framework
The methodology follows the **Penetration Testing Execution Standard (PTES)**, covering the following phases:
1. **Pre-engagement:** Scope definition and objective setting.
2. **Reconnaissance:** Intelligence gathering and network mapping.
3. **Discovery/Scanning:** Technical examination of targets.
4. **Vulnerability Analysis:** Identifying misconfigurations (AS-REP Roasting, Kerberoasting).
5. **Exploitation:** Gaining initial access and lateral movement.
6. **Post-Exploitation:** Privilege escalation and maintaining access.
7. **Reporting & Remediation:** Executive summary and technical recommendations.

---

## ⚙️ Vulnerable Lab Configuration (Setup Guide)

To replicate the attack path demonstrated in this project, the following **Active Directory misconfigurations** must be intentionally implemented within the `startup.local` domain:

### 1. AS-REP Roasting Setup (`setya.ramadan`)
The goal is to allow an attacker to request an authentication ticket without providing a password initially.
* **Target Account**: `setya.ramadan`.
* **Misconfiguration**: Disable Kerberos Pre-Authentication.
* **How-to**: 
    * Open **Active Directory Users and Computers (ADUC)**.
    * Navigate to the Properties of the `setya.ramadan` account.
    * Under the **Account** tab, in the **Account options** list, check the box: **"Do not require Kerberos preauthentication"**.
    * Ensure the password is set to something common (e.g., `Rama123!`) for successful offline cracking.

### 2. Kerberoasting Setup (`svc.backup`)
This involves creating a service account that is vulnerable to ticket extraction.
* **Target Account**: `svc.backup`.
* **Misconfiguration**: Register a Service Principal Name (SPN) to a standard user account.
* **How-to**:
    * Run the following command in an elevated prompt on the Domain Controller to register an SPN:
      `setspn -A HTTP/backup.startup.local svc.backup`.
    * Assign a weak password to this account to ensure the TGS ticket can be cracked offline.

### 3. Delegation Abuse & ACL Misconfiguration
This setup creates a path for privilege escalation through abused permissions.
* **Target Group**: `IT_Support` (containing `svc.backup`).
* **Privileged Target**: `it.manager` (within a Privileged OU).
* **Misconfiguration**: Grant "Reset Password" permissions via Delegated Control.
* **How-to**:
    * Right-click the **Organizational Unit (OU)** containing `it.manager`.
    * Select **Delegate Control** and add the `IT_Support` group.
    * Choose **"Reset user passwords and force password change at next logon"** as the delegated task.
    * Ensure `it.manager` is a member of elevated groups like **Server Operators** or **Administrators** to complete the escalation.

### 4. Remote Management Exposure
To allow the attacker to gain a foothold, remote management services must be accessible.
* **Configuration**: Enable **WinRM (Windows Remote Management)** on the Windows 10 Workstation.
* **How-to**:
    * On the Workstation, run `Enable-PSRemoting -Force` in PowerShell.
    * Ensure the firewall allows traffic on **TCP Port 5985** (HTTP) from the Attacker's subnet.
