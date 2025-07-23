import paramiko
import requests
import base64
import secrets
import string
import time
import os
import xml.etree.ElementTree as ET
import tempfile

# =========================
# CONFIGURATION SECTION
# =========================

TOMCAT_IP = "182.12.0.13"
SSH_USER = "ubuntu"
TOMCAT_USER = "tomcat-user"
TOMCAT_XML_PATH = "/usr/local/tomcat/conf/tomcat-users.xml"

JENKINS_URL = "http://182.12.0.12:8080"
JENKINS_USER = "admin"
JENKINS_TOKEN = "1142f244c61fa8d305a7b69c940e32a897"
CREDENTIAL_ID = "tomcat-credentials"

SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

# =========================
# FUNCTION DEFINITIONS
# =========================

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def update_tomcat_user_xml(local_path, username, password):
    ET.register_namespace('', "http://tomcat.apache.org/xml")
    tree = ET.parse(local_path)
    root = tree.getroot()

    # Remove any existing users with this username
    for user in root.findall('user'):
        if user.attrib.get('username') == username:
            root.remove(user)

    # Add new user element
    new_user = ET.Element('user', {
        'username': username,
        'password': password,
        'roles': 'manager-gui'
    })
    root.append(new_user)

    tree.write(local_path, encoding="utf-8", xml_declaration=True)

def update_tomcat_user_remote(ip, user, key_path, tomcat_user, tomcat_pass, xml_path):
    print("[*] Connecting to Tomcat server via SSH key...")
    key = paramiko.RSAKey.from_private_key_file(key_path)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=user, pkey=key)
    sftp = ssh.open_sftp()

    print("[*] Downloading tomcat-users.xml...")
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        local_path = tmpfile.name
        sftp.get(xml_path, local_path)

    print("[*] Backing up remote tomcat-users.xml...")
    ssh.exec_command(f"cp {xml_path} {xml_path}.bak")

    print("[*] Modifying XML locally...")
    update_tomcat_user_xml(local_path, tomcat_user, tomcat_pass)

    print("[*] Uploading updated XML...")
    sftp.put(local_path, xml_path)

    print("[*] Restarting Tomcat service...")
    stdin, stdout, stderr = ssh.exec_command("sudo systemctl restart tomcat || sudo systemctl restart tomcat9")
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[!] Error restarting Tomcat:\n{stderr.read().decode()}")
    else:
        print("[✓] Tomcat restarted successfully.")

    sftp.close()
    ssh.close()

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
    print("=== Tomcat + Jenkins Credential Sync Script (XML-safe mode) ===")

    new_pass = generate_password()
    print(f"[*] Generated new password for {TOMCAT_USER}: {new_pass}")

    # Step 1: Update Tomcat Server via SSH + XML
    update_tomcat_user_remote(TOMCAT_IP, SSH_USER, SSH_KEY_PATH, TOMCAT_USER, new_pass, TOMCAT_XML_PATH)

    time.sleep(5)

    # Step 2: Update Jenkins Credentials
    update_jenkins_credentials(JENKINS_URL, CREDENTIAL_ID, TOMCAT_USER, new_pass, JENKINS_USER, JENKINS_TOKEN)

    print("✅ All tasks completed successfully!")

if __name__ == "__main__":
    main()
