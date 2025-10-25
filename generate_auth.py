#!/usr/bin/env python2
import base64
import sys

def create_basic_auth(username, password):
    token = "{}:{}".format(username, password)
    return base64.b64encode(token)

def main():
    if len(sys.argv) < 3:
        print("Usage: python2 script.py <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]
    auth_b64 = create_basic_auth(username, password)

    # Print only the Base64 value (no JSON, no labels)
    print(auth_b64)

if __name__ == "__main__":
    main()
