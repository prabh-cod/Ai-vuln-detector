# 🛡️ AI-VULN-DETECTOR

An Enterprise-Grade Static Application Security Testing (SAST) tool built in Python. 
Moving beyond basic rule-based regex matching, this engine utilizes **Abstract Syntax Tree (AST) Parsing** and **Taint Analysis (Data Flow)** to catch critical vulnerabilities before they reach production.

## ✨ Core Features
- **Taint Tracking (Data Flow Analysis):** Traces user inputs to detect active Remote Code Execution (RCE) via `eval()` or `exec()`.
- **Advanced Signature Matching:** Detects Hardcoded Credentials, API Keys, and plaintext secrets assigned to variables.
- **Command Injection Prevention:** Flags unsafe usage of the `subprocess` module.
- **Insecure Import Detection:** Identifies the use of vulnerable standard libraries like `pickle`, `telnetlib`, and `ftplib`.
- **AI Remediation Engine:** Doesn't just find the bug—it suggests the exact code refactoring needed to fix it.
- **CI/CD Ready:** Automatically generates timestamped `.json` security artifact reports for enterprise pipelines.

## 🚀 How to Run