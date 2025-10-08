#!/usr/bin/env python3
import os
import base64
import secrets
import string
import requests

# ======== CONFIG ========
JENKINS_URL = os.getenv("JENKINS_URL", "http://localhost:8080")
JENKINS_USER = os.getenv("JENKINS_USER", "admin")
JENKINS_API_TOKEN = os.getenv("JENKINS_API_TOKEN", "")
CREDENTIAL_ID = "generated-auth"   # You can make this dynamic if needed
# ========================

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def create_basic_auth(username, password):
    token = f"{username}:{password}"
    return base64.b64encode(token.encode()).decode()

def save_to_jenkins_credentials(username, password):
    """
    Adds username & password to Jenkins credentials store using REST API.
    """
    # Jenkins Crumb for CSRF protection
    crumb_data = requests.get(
        f"{JENKINS_URL}/crumbIssuer/api/json",
        auth=(JENKINS_USER, JENKINS_API_TOKEN)
    ).json()
    
    crumb = {crumb_data['crumbRequestField']: crumb_data['crumb']}

    payload = {
        "": "0",
        "credentials": {
            "scope": "GLOBAL",
            "id": CREDENTIAL_ID,
            "username": username,
            "password": password,
            "description": "Auto-generated Basic Auth Credential",
            "$class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
        }
    }

    response = requests.post(
        f"{JENKINS_URL}/credentials/store/system/domain/_/createCredentials",
        headers={**crumb, "Content-Type": "application/json"},
        json=payload,
        auth=(JENKINS_USER, JENKINS_API_TOKEN)
    )

    if response.status_code == 200:
        print(f"✅ Credentials '{CREDENTIAL_ID}' saved successfully in Jenkins.")
    else:
        print(f"❌ Failed to save credentials: {response.status_code} {response.text}")

def main():
    # Step 1: Get username from Jenkins input parameter (or CLI)
    username = os.getenv("INPUT_USERNAME") or input("Enter username: ")

    # Step 2: Generate password
    password = generate_password()

    # Step 3: Encode Basic Auth
    auth_base64 = create_basic_auth(username, password)
    print(f"Base64 Token: {auth_base64}")

    # Step 4: Save to Jenkins Credentials
    save_to_jenkins_credentials(username, password)

if __name__ == "__main__":
    main()
