# 🛡️ PQC-NetCheck: Wire-Level TLS 1.3 Telemetry & PQC Scanner

> **Early lab prototype — not production.** Capture and parsing behavior, protocol coverage, permissions, and result interpretation require validation on the target system. Do not treat output as a complete PQC readiness assessment.

## 📌 Overview
PQC-NetCheck is a specialized VS Code extension engineered for Cybersecurity Architects and PQC Migration Specialists. Instead of relying on surface-level vendor compliance dashboards, this tool performs rigorous, ground-truth analysis by intercepting live TLS 1.3 ClientHello packets directly on the wire to empirically verify Post-Quantum Cryptography (PQC) readiness.

## 🔬 Core Architecture & Features
* **Live Wire-Level Interception:** Integrates directly with `tshark` to sniff real-time network telemetry.
* **Deep Packet Inspection (TLS 1.3):** Extracts TLS Extension 10 (Supported Groups) to identify negotiated cryptographic OIDs.
* **PQC vs Classical Mapping:** Automatically distinguishes between hybrid PQC algorithms (e.g., ML-KEM/Kyber drafts like `0x11ab`, `0x6399`) and classical elliptic curves (e.g., X25519, SECP256R1).
* **Dual-Stack Telemetry:** Seamlessly captures and resolves both IPv4 and IPv6 traffic sources.

## ⚙️ Prerequisites
* **Wireshark (`tshark`):** Must be installed and configured in the system PATH.
* **Npcap/WinPcap:** Required for live packet capture on Windows interfaces.
* **Node.js & VS Code:** For compiling and running the extension host.

## 🚀 Quick Start & Usage
1. Clone the repository and install dependencies: `npm install`
2. Compile the TypeScript code: `npm run compile`
3. Press `F5` to launch the Extension Development Host.
4. Open the Command Palette (`Ctrl+Shift+P`) and execute: `PQC-NetCheck: Scan Network`.
5. Generate HTTPS traffic in your browser to view real-time cryptographic negotiations on the PQC Pulse Dashboard.

## 🧠 Engineering Philosophy
Built on a first-principles mindset: **"Verify at the wire."** A rigorous Post-Quantum migration strategy requires empirical packet-level verification, distinguishing actual negotiated TLS groups from theoretical compliance.