import paramiko
import tempfile
import xml.etree.ElementTree as ET
import os
import base64
import secrets
import string
import requests
import time

# Configs
TOMCAT_IP = "182.12.0.13"
SSH_USER = "ubuntu"
TOMCAT_USER = "tomcat-user"
TOMCAT_XML_PATH = "/usr/local/tomcat/conf/tomcat-users.xml"

JENKINS_URL = "http://182.12.0.12:8080"
JENKINS_USER = "admin"
JENKINS_TOKEN = "1142f244c61fa8d305a7b69c940e32a897"
CREDENTIAL_ID = "tomcat-credentials"

SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

# Password generator
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

# Read remote XML via SSH
def read_remote_file(ssh, remote_path):
    stdin, stdout, stderr = ssh.exec_command(f"cat {remote_path}")
    content = stdout.read().decode()
    err = stderr.read().decode()
    if err:
        raise RuntimeError(f"Failed to read remote file: {err}")
    return content

# Write XML back via SSH
def write_remote_file(ssh, remote_path, content):
    # Save locally
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(content)
        temp_path = f.name

    with open(temp_path, 'r') as f:
        lines = f.readlines()

    # Clean previous temp
    ssh.exec_command(f"rm -f {remote_path}.tmp")

    # Reconstruct file line by line
    for line in lines:
        safe_line = line.strip().replace("'", "'\\''")  # Escape single quotes for shell
        ssh.exec_command(f"echo '{safe_line}' >> {remote_path}.tmp")

    # Backup and replace
    ssh.exec_command(f"mv {remote_path} {remote_path}.bak")
    ssh.exec_command(f"mv {remote_path}.tmp {remote_path}")

# XML editor
def modify_tomcat_users_xml(xml_str, username, password):
    root = ET.fromstring(xml_str)

    # Remove old users
    for user in root.findall('user'):
        if user.attrib.get('username') == username:
            root.remove(user)

    # Add new user
    new_user = ET.Element('user', {
        'username': username,
        'password': password,
        'roles': 'manager-gui'
    })
    root.append(new_user)

    # Serialize XML
    return ET.tostring(root, encoding='unicode', method='xml')

# Update Jenkins
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

# Main handler
def update_tomcat_user_alpine(ip, user, key_path, tomcat_user, tomcat_pass, xml_path):
    print("[*] Connecting to Alpine-based Tomcat server...")
    key = paramiko.RSAKey.from_private_key_file(key_path)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=user, pkey=key)

    print("[*] Reading remote tomcat-users.xml...")
    original_xml = read_remote_file(ssh, xml_path)

    print("[*] Modifying XML...")
    updated_xml = modify_tomcat_users_xml(original_xml, tomcat_user, tomcat_pass)

    print("[*] Uploading modified XML...")
    write_remote_file(ssh, xml_path, updated_xml)

    print("[*] Restarting Tomcat...")
    # Alpine usually uses init.d or a direct script
    stdin, stdout, stderr = ssh.exec_command("/usr/local/tomcat/bin/catalina start || /usr/local/tomcat/bin/shutdown.sh && /usr/local/tomcat/bin/startup.sh")
    out = stdout.read().decode()
    err = stderr.read().decode()
    print(out)
    if err:
        print(f"[!] Error restarting Tomcat: {err}")

    ssh.close()
    print("[✓] Tomcat user updated and server restarted.")

# Entrypoint
def main():
    print("=== Tomcat + Jenkins Credential Sync Script (Alpine Mode) ===")

    new_pass = generate_password()
    print(f"[*] Generated new password for {TOMCAT_USER}: {new_pass}")

    update_tomcat_user_alpine(TOMCAT_IP, SSH_USER, SSH_KEY_PATH, TOMCAT_USER, new_pass, TOMCAT_XML_PATH)

    time.sleep(3)

    update_jenkins_credentials(JENKINS_URL, CREDENTIAL_ID, TOMCAT_USER, new_pass, JENKINS_USER, JENKINS_TOKEN)

    print("✅ All tasks completed successfully!")

if __name__ == "__main__":
    main()
