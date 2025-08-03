import httplib
import json
import os
import sys
import base64
import random
import string

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    # Use os.urandom for cryptographic randomness
    secure_random = random.SystemRandom()
    return ''.join(secure_random.choice(chars) for _ in range(length))

# Jenkins and Tomcat config
JENKINS_HOST = sys.argv[1]
JENKINS_PORT = 8080
JENKINS_USER = sys.argv[2]
JENKINS_TOKEN = sys.argv[3]
NEW_PASSWORD =  generate_password(20)
TOMCAT_HOST = sys.argv[4]
TOMCAT_PORT = 8082
TOMCAT_USER = sys.argv[5]
TOMCAT_PASS = sys.argv[6]  # Same as Jenkins credential
CREDENTIAL_ID = sys.argv[7]

def get_auth_header(user, token):
    auth = base64.b64encode('%s:%s' % (user, token))
    return {'Authorization': 'Basic %s' % auth}

def update_jenkins_credential():
    conn = httplib.HTTPConnection(JENKINS_HOST, JENKINS_PORT)
    headers = get_auth_header(JENKINS_USER, JENKINS_TOKEN)
    headers['Content-Type'] = 'application/json'

    # Construct payload to update credential
    payload = {
        "": "0",
        "credentials": {
            "scope": "GLOBAL",
            "id": CREDENTIAL_ID,
            "username": TOMCAT_USER,
            "password": NEW_PASSWORD,
            "description": "Updated Tomcat user password",
            "$class": "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
        }
    }

    json_data = json.dumps(payload)

    # Jenkins API endpoint to update credentials
    endpoint = '/credentials/store/system/domain/_/credential/%s/config.xml' % CREDENTIAL_ID
    conn.request('POST', endpoint, json_data, headers)
    response = conn.getresponse()
    print("Jenkins response:", response.status, response.reason)
    conn.close()

def update_tomcat_user():
    conn = httplib.HTTPConnection(TOMCAT_HOST, TOMCAT_PORT)
    headers = get_auth_header(TOMCAT_USER, TOMCAT_PASS)
    headers['Content-Type'] = 'application/json'

    # Example: Send a dummy request to verify password works
    conn.request('GET', '/manager/text/list', '', headers)
    response = conn.getresponse()
    print("Tomcat response:", response.status, response.reason)
    conn.close()

if __name__ == '__main__':
    update_jenkins_credential()
    update_tomcat_user()
