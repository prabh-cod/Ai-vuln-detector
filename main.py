import ast
import json
import os
import sys
import pandas as pd
from datetime import datetime

class EnterpriseVulnVisitor(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []
        self.tainted_variables = set()
    def visit_Assign(self, node):
        # 1. TAINT ANALYSIS: Track variables holding user input
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if node.value.func.id in ['input', 'sys.stdin.read']:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_variables.add(target.id)

        # 2. CREDENTIAL SCANNING
        for target in node.targets:
            if isinstance(target, ast.Name):
                if any(kw in target.id.lower() for kw in ['password', 'secret', 'api_key', 'token']):
                    if isinstance(node.value, ast.Constant):
                        self.vulnerabilities.append({
                            'Line': node.lineno,
                            'Risk_Level': 'CRITICAL',
                            'Vulnerability': f'Hardcoded Secret assigned to "{target.id}"',
                            'AI_Remediation': f'Do not store "{target.id}" in plaintext. Use: os.getenv("{target.id.upper()}")'
                        })
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            # 3. REMOTE CODE EXECUTION (RCE)
            if func_name in ['eval', 'exec']:
                is_tainted = any(isinstance(arg, ast.Name) and arg.id in self.tainted_variables for arg in node.args)
                
                if is_tainted:
                    self.vulnerabilities.append({
                        'Line': node.lineno,
                        'Risk_Level': 'CRITICAL (Active RCE)',
                        'Vulnerability': f'User-controlled data passed directly into {func_name}()',
                        'AI_Remediation': f'NEVER pass raw user input to {func_name}(). Use ast.literal_eval() for safe string parsing.'
                    })
                else:
                    self.vulnerabilities.append({
                        'Line': node.lineno,
                        'Risk_Level': 'HIGH',
                        'Vulnerability': f'Dynamic execution via {func_name}() detected',
                        'AI_Remediation': 'Refactor code to avoid dynamic execution entirely.'
                    })

            # 4. COMMAND INJECTION
            elif func_name == 'subprocess':
                self.vulnerabilities.append({
                    'Line': node.lineno,
                    'Risk_Level': 'MEDIUM',
                    'Vulnerability': 'Subprocess spawned; check for shell=True injection',
                    'AI_Remediation': 'Pass commands as a strictly defined List, e.g., ["ls", "-la"], never use shell=True.'
                })
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in ['pickle', 'telnetlib', 'ftplib']:
                self.vulnerabilities.append({
                    'Line': node.lineno,
                    'Risk_Level': 'MEDIUM',
                    'Vulnerability': f'Insecure standard library imported: "{alias.name}"',
                    'AI_Remediation': f'"{alias.name}" is unsafe. For serialization, swap to the "json" module.'
                })
        self.generic_visit(node)

def scan_engine(file_path, export_json=True):
    if not os.path.exists(file_path):
        print(f"[!] Error: Target file '{file_path}' does not exist.")
        return

    print(f"\n[*] Booting AI-VULN-DETECTOR Core...")
    print(f"[*] Target AST Target: {file_path}")
    print("-" * 65)

    with open(file_path, 'r') as f:
        code_content = f.read()

    tree = ast.parse(code_content)
    scanner = EnterpriseVulnVisitor()
    scanner.visit(tree)

    if not scanner.vulnerabilities:
        print("[+] SUCCESS: 0 Vulnerabilities Detected. Code is clean.")
        return

    # Create visual console output
    df = pd.DataFrame(scanner.vulnerabilities)
    df = df[['Line', 'Risk_Level', 'Vulnerability', 'AI_Remediation']]
    
    # Print clean table to terminal
    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_colwidth', 40)
    print(df.to_string(index=False))
    print("-" * 65)

    # Enterprise Feature: Auto-generate a CI/CD JSON report
    if export_json:
        report_data = {
            "scan_timestamp": datetime.now().isoformat(),
            "target_scanned": file_path,
            "total_threats_found": len(scanner.vulnerabilities),
            "threat_log": scanner.vulnerabilities
        }
        report_name = f"security_report_{int(datetime.now().timestamp())}.json"
        with open(report_name, 'w') as jf:
            json.dump(report_data, jf, indent=4)
        print(f"[+] Enterprise Artifact Generated: Saved to '{report_name}'")

if __name__ == "__main__":
    target = 'test.py'
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
    scan_engine(target)