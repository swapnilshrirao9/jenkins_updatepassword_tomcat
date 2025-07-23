import paramiko
import requests
import base64
import secrets
import string
import time
import os

# =========================
# CONFIGURATION SECTION
# =========================

# Tomcat Server Info
TOMCAT_IP = "182.12.0.13"         # <<<< Tomcat server IP
SSH_USER = "ubuntu"               # <<<< SSH user (key-based login)
TOMCAT_USER = "tomcat-user"
TOMCAT_XML_PATH = "/usr/local/tomcat/conf/tomcat-users.xml"

# Jenkins Info
JENKINS_URL = "http://182.12.0.12:8080"  # <<<< Jenkins server IP
JENKINS_USER = "admin"                   # <<<< Jenkins admin user
JENKINS_TOKEN = "1142f244c61fa8d305a7b69c940e32a897" # <<<< Jenkins API token
CREDENTIAL_ID = "tomcat-credentials"      # <<<< Jenkins credential ID

# SSH Key Path (default: ~/.ssh/id_rsa)
SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")  # <<<< Update if using a different key

# =========================
# FUNCTION DEFINITIONS
# =========================

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def update_tomcat_user_remote(ip, user, key_path, tomcat_user, tomcat_pass, xml_path):
    print("[*] Connecting to Tomcat server via SSH key...")
    key = paramiko.RSAKey.from_private_key_file(key_path)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=user, pkey=key)

    print("[*] Backing up tomcat-users.xml...")
    ssh.exec_command(f"cp {xml_path} {xml_path}.bak")

    print("[*] Removing any existing user entry...")
    ssh.exec_command(f"sed -i '/username=\\\"{tomcat_user}\\\"/d' {xml_path}")

    print("[*] Inserting new user entry...")
    insert_user_cmd = f"""sed -i '/<\\/tomcat-users>/i\\  <user username=\\"{tomcat_user}\\" password=\\"{tomcat_pass}\\" roles=\\"manager-gui\\"/>' {xml_path}"""
    ssh.exec_command(insert_user_cmd)

    print("[*] Restarting Tomcat...")
    ssh.exec_command("sudo systemctl restart tomcat || sudo systemctl restart tomcat9")
    ssh.close()

    print("[✓] Tomcat user updated and Tomcat restarted.")

def update_jenkins_credentials(jenkins_url, cred_id, username, password, j_user, j_token):
    print("[*] Updating Jenkins credentials...")
    cred_url = f"{jenkins_url}/credentials/store/system/domain/_/credential/{cred_id}/config.xml"

    auth_header = base64.b64encode(f"{j_user}:{j_token}".encode()).decode()
    headers = {
        'Authorization': f'Basic {auth_header}',
        'Content-Type': 'application/xml'
    }

    xml_payload = f"""<com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
  <scope>GLOBAL</scope>
  <id>{cred_id}</id>
  <description>Auto-updated Tomcat password</description>
  <username>{username}</username>
  <password>{password}</password>
</com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>"""

    response = requests.post(cred_url, headers=headers, data=xml_payload)

    if response.status_code == 200:
        print("[✓] Jenkins credentials updated successfully.")
    else:
        print(f"[!] Failed to update Jenkins credentials. Status: {response.status_code}")
        print(response.text)

# =========================
# MAIN EXECUTION
# =========================

def main():
    print("=== Tomcat + Jenkins Credential Sync Script (SSH Key Mode) ===")

    new_pass = generate_password()
    print(f"[*] Generated new password for {TOMCAT_USER}: {new_pass}")

    # Step 1: Update Tomcat Server via SSH Key
    update_tomcat_user_remote(TOMCAT_IP, SSH_USER, SSH_KEY_PATH, TOMCAT_USER, new_pass, TOMCAT_XML_PATH)

    # Wait for Tomcat restart
    time.sleep(5)

    # Step 2: Update Jenkins Credentials
    update_jenkins_credentials(JENKINS_URL, CREDENTIAL_ID, TOMCAT_USER, new_pass, JENKINS_USER, JENKINS_TOKEN)

    print("✅ All tasks completed successfully!")

if __name__ == "__main__":
    main()
