#!/usr/bin/env python2
import base64
import random
import string
import json
import sys

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    secure_rand = random.SystemRandom()
    return ''.join(secure_rand.choice(chars) for _ in range(length))

def create_basic_auth(username, password):
    token = "{}:{}".format(username, password)
    return base64.b64encode(token)

def main():
    if len(sys.argv) < 2:
        print("Usage: python2 generate_auth.py <username>")
        sys.exit(1)
    username = sys.argv[1]
    password = generate_password()
    auth_b64 = create_basic_auth(username, password)

# Output JSON
  print(auth_b64)
if __name__ == "__main__":

    main()
