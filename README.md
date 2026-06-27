# VroG – Security & Administration Dashboard

**VroG** is a lightweight, multi-threaded security and system administration dashboard developed for **Kali Linux**. Built with **Python** and **Tkinter**, it combines essential cybersecurity and administrative utilities into a single, user-friendly graphical interface while maintaining low system resource usage.

## 🚀 Features

### 🔍 Port Scanner

A fast, multi-threaded TCP port scanner that identifies open ports on target IP addresses or hostnames, enabling quick network reconnaissance.

### 🔐 Password Generator & Credential Manager

Generate strong, random 16-character passwords and securely store credentials in a local **SQLite** database (`vrog_vault.db`) for offline access.

### 📄 Log Analyzer

Analyze system log files by automatically detecting and highlighting **CRITICAL**, **ERROR**, and **WARNING** entries, making it easier to identify potential security issues.

### 🛠️ System Audit & Vulnerability Scanner

A wrapper that automates basic system security checks, including patch verification and local network interface inspection, providing a quick overview of system health.

### 🎣 Phishing Awareness Simulator

An educational phishing simulation powered by **Flask**, allowing users to safely learn how phishing attacks work and recognize common social engineering techniques in a controlled environment.

### 🌐 DNS Lookup Utility

Perform DNS queries through the native operating system `nslookup` command to retrieve domain records and troubleshoot DNS-related issues.

---

## ⚙️ Prerequisites

Before running VroG, ensure your system meets the following requirements:

* **Operating System:** Kali Linux (recommended) or any Debian-based Linux distribution
* **Python:** Version 3.x or later
* **GUI Library:** Tkinter (installed at the operating system level)
* **Dependencies:** Python packages listed in `requirements.txt`

---

## 🎯 Key Highlights

* Lightweight and resource-efficient
* Multi-threaded architecture for improved performance
* Intuitive graphical user interface built with Tkinter
* Offline credential storage using SQLite
* Modular design for easy maintenance and future expansion
* Designed specifically for cybersecurity learning and system administration tasks on Linux
