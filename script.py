import paramiko
import os
import base64
import secrets
import string
import requests
import time

# === Configuration ===
TOMCAT_IP = "182.12.0.13"
SSH_USER = "ubuntu"
TOMCAT_USER = "tomcat"
TOMCAT_XML_PATH = "/usr/local/tomcat/conf/tomcat-users.xml"

JENKINS_URL = "http://182.12.0.12:8080"
JENKINS_USER = "admin"
JENKINS_TOKEN = "1142f244c61fa8d305a7b69c940e32a897"
CREDENTIAL_ID = "tomcat-credentials"

SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

# === Password Generator ===
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

# === Write using sed on remote ===
def write_remote_file(ssh, remote_path, username, new_password):
    # Escape special characters for sed
    escaped_pass = new_password.replace('&', '\\&').replace('$', '\\$').replace('`', '\\`').replace('"', '\\"').replace('`', '\\`').replace("'", "'\"'\"'")

    print(f"[*] Updating password for user '{username}' in remote tomcat-users.xml...")

    # Backup the original file
    ssh.exec_command(f"cp {remote_path} {remote_path}.bak")

    # sed command to replace password for matching user
    sed_cmd = f"sed -i 's/\\(<user[^>]*username=[\"\\'']{username}[\"\\''][^>]*password=[\"\\'']\\)[^\"\\'']*\\([\"\\''][^>]*>\\)/\\1{escaped_pass}\\2/' {remote_path}"

    stdin, stdout, stderr = ssh.exec_command(sed_cmd)
    err = stderr.read().decode()
    if err:
        print(f"[!] Error updating file with sed: {err}")
    else:
        print("[✓] Password updated via sed.")

# === Jenkins Credential Update ===
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

# === Main Tomcat Update ===
def update_tomcat_user_sed(ip, user, key_path, tomcat_user, tomcat_pass, xml_path):
    print("[*] Connecting to Tomcat server via SSH...")
    key = paramiko.RSAKey.from_private_key_file(key_path)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=user, pkey=key)

    # Step 1: Stop Tomcat first
    print("[*] Stopping Tomcat...")
    ssh.exec_command("/usr/local/tomcat/bin/shutdown.sh")
    time.sleep(5)

    # Step 2: Prepare sed command
    print("[*] Updating tomcat-users.xml via sed...")

    temp_file = "/tmp/tomcat-users.xml.tmp"
    escaped_pass = tomcat_pass.replace('&', '\\&').replace('$', '\\$').replace('`', '\\`').replace('"', '\\"').replace("'", "'\"'\"'")

    sed_cmd = (
        f"sed 's/\\(<user[^>]*username=[\"\\'']{tomcat_user}[\"\\''][^>]*password=[\"\\'']\\)[^\"\\'']*\\([\"\\''][^>]*>\\)/\\1{escaped_pass}\\2/' "
        f"{xml_path} > {temp_file} && cp {xml_path} {xml_path}.bak && mv {temp_file} {xml_path}"
    )

    stdin, stdout, stderr = ssh.exec_command(sed_cmd)
    err = stderr.read().decode()
    if err:
        print(f"[!] Error updating file with sed: {err}")
    else:
        print("[✓] Password updated in tomcat-users.xml.")

    # Step 3: Restart Tomcat
    print("[*] Starting Tomcat...")
    ssh.exec_command("/usr/local/tomcat/bin/startup.sh")
    time.sleep(3)

    ssh.close()
    print("[✓] Tomcat restarted successfully.")


# === Entrypoint ===
def main():
    print("=== Tomcat + Jenkins Credential Sync Script (sed version) ===")

    new_pass = generate_password()
    print(f"[*] Generated new password for user '{TOMCAT_USER}': {new_pass}")

    update_tomcat_user_sed(TOMCAT_IP, SSH_USER, SSH_KEY_PATH, TOMCAT_USER, new_pass, TOMCAT_XML_PATH)

    time.sleep(3)

    update_jenkins_credentials(JENKINS_URL, CREDENTIAL_ID, TOMCAT_USER, new_pass, JENKINS_USER, JENKINS_TOKEN)

    print("✅ All tasks completed successfully!")

if __name__ == "__main__":
    main()
