---
title: "AI-Augmented SOC: Wazuh + Discord + LLM Integration"
description: "an automated Security Operations Center (SOC) pipeline that detects, analyzes, and triages security events in real time using Wazuh SIEM, Discord (ChatOps interface), Google Gemini (LLM-based threat analysis)"
publishDate: 2026-04-01
tags:
  - "Wazuh"
  - "Google Gemini"
  - "Discord"
  - "SOC Analyst"
  - "AI"
  - "Automation Tool"
image: "/assets/works/wazuhndc.png"
order: 3
isShow: true
---

## 📌 Project Overview

⚠️ For full scripts and explanation, you can visit my github: https://github.com/ramveil/Automated-Threat-Detection-and-Triage-using-a-Wazuh-Discord-Integration-and-Large-Language-Models

This project implements an **automated Security Operations Center (SOC) pipeline** that detects, analyzes, and triages security events in real time using:

* Wazuh SIEM
* Discord (ChatOps interface)
* Google Gemini (LLM-based threat analysis)

The system transforms raw logs into actionable intelligence and delivers alerts directly to analysts via Discord.

---

## 🧠 Architecture

The system follows an **event-driven pipeline**:

1. Wazuh Agent collects logs from endpoints
2. Wazuh Manager analyzes events using rules
3. High-severity alerts trigger a custom integration script
4. Alert data is enriched using a Large Language Model
5. Structured alerts are sent to Discord
6. Analysts interact with alerts via buttons (WHOIS / FULL LOG)

📌 As described in the system design, alerts are processed, enriched, and transmitted in real-time using an asynchronous pipeline 

---

## ⚙️ Infrastructure

| Role        | System      | Description          |
| ----------- | ----------- | -------------------- |
| Attacker    | Kali Linux  | Simulated attacks    |
| Target      | Ubuntu      | Victim machine       |
| SIEM Server | Ubuntu      | Wazuh Manager        |
| ChatOps     | Discord Bot | Alert interface      |
| AI Engine   | Gemini API  | Threat summarization |

---

## 🚀 Features

* 🔍 Real-time threat detection (Wazuh)
* 🤖 AI-powered alert summarization
* 💬 Discord-based SOC dashboard
* 🕵️ WHOIS lookup integration
* 📜 Raw log retrieval via chat interaction
* ⚡ Asynchronous alert delivery (instant notification + delayed AI insight)

---

## 🔧 Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 2. Configure environment

Create `.env`:

```env
GEMINI_API_KEY=your_key
DISCORD_BOT_TOKEN=your_token
CHANNEL_ID=your_channel_id
```

---

### 3. Deploy Wazuh Integration

Copy script to:

```bash
/var/ossec/integrations/custom-discord.py
```

---

### 4. Run Discord Bot

```bash
python bot/discord_listener.py
```

---

## 🔄 Detection & Alert Flow

### 🔐 SSH Brute Force Attack

1. Attacker performs SSH login attempts
2. Wazuh detects authentication failures
3. Alert reaches threshold (Level ≥ 5)
4. Integration script triggers

---

### ⚡ Alert Processing Pipeline

1. Alert sent instantly to Discord ("Processing...")
2. LLM analyzes log data
3. Message updated with AI-generated insight

📌 This design ensures no delay in alert visibility while AI processes in background 

---

### 🧠 Interactive Triage

* **WHOIS Button** → Fetch IP intelligence
* **FULL LOG Button** → Retrieve raw syslog

---

## 💥 Example Attack Scenario

* Brute-force attack escalates to successful login
* Wazuh triggers **Level 12 critical alert**
* Discord displays alert with AI summary
* Analyst retrieves raw logs and confirms compromise

📌 As shown in testing, successful credential compromise is detected and escalated with contextual intelligence 

---

## 🛡️ Mitigation

* Block attacker IP using Wazuh active response:

```bash
sudo /var/ossec/bin/agent_control -b <attacker_ip> -f firewall-drop0
```