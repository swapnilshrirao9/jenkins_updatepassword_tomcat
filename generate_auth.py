#!/usr/bin/env python3
import base64
import secrets
import string
import json
import sys
import os

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def create_basic_auth(username, password):
    token = f"{username}:{password}"
    return base64.b64encode(token.encode()).decode()

def main():
    username = sys.argv[1]
    password = generate_password()
    auth_b64 = create_basic_auth(username, password)
    
    # Output JSON for easy capture in Jenkins
    result = {
        "username": username,
        "password": password,
        "auth_base64": auth_b64
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
