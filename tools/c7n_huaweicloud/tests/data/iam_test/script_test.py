#!/usr/bin/env python
import logging
import os
import sys

log = logging.getLogger("c7n-org.script_test.py")

def main():
    print("Script execution start.")
    print(f"account: {os.getenv("HUAWEICLOUD_ACCESS_KEY_ID")}, "
          f"{os.getenv("HUAWEICLOUD_SECRET_ACCESS_KEY")}, "
          f"{os.getenv("HUAWEICLOUD_REGION")}, "
          f"{os.getenv("HUAWEICLOUD_DOMAIN_NAME")}, "
          f"{os.getenv("HUAWEICLOUD_DOMAIN_ID")}, "
          f"{os.getenv("HUAWEICLOUD_DOMAIN_STATUS")}, "
          f"{os.getenv("HUAWEICLOUD_SECURITY_TOKEN")}")

    print("Script execution completed")
    return 0


if __name__ == '__main__':
    sys.exit(main())