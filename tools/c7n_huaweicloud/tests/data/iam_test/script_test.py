#!/usr/bin/env python
import logging
import os
import sys

log = logging.getLogger("c7n-org.script_test.py")

def main():
    print("Script execution start.")
    print(f"account region: {os.getenv("HUAWEICLOUD_REGION")}")
    print(f"account name: {os.getenv("HUAWEICLOUD_DOMAIN_NAME")}")
    print(f"account id: {os.getenv("HUAWEICLOUD_DOMAIN_ID")}")
    print(f"account status: {os.getenv("HUAWEICLOUD_DOMAIN_STATUS")}")
    print(f"account ak: {os.getenv("HUAWEICLOUD_ACCESS_KEY_ID")}")
    print(f"account sk: {os.getenv("HUAWEICLOUD_SECRET_ACCESS_KEY")}")
    print(f"account token: {os.getenv("HUAWEICLOUD_SECURITY_TOKEN")}")
    print("Script execution completed")
    return 0


if __name__ == '__main__':
    sys.exit(main())