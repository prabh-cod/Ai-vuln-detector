import pickle
import subprocess

# Threat 1: Hardcoded API Key
google_cloud_api_key = "AIzaSyC_super_secret_production_key"

# Threat 2: Tainted Data Flow (User input going to Eval)
user_prompt = input("Type a command: ")
eval(user_prompt)

# Threat 3: Normal eval
eval("2 + 2")

# Threat 4: Command Injection Risk
subprocess.Popen("ls -la", shell=True)