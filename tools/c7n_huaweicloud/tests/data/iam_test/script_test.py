#!/usr/bin/env python
import json
import logging
import os
import sys
from c7n.commands import validate as validate_cmd

log = logging.getLogger("c7n-org.script_test.py")

def main():
    log.info(f"ak is:{os.getenv("HUAWEICLOUD_ACCESS_KEY_ID")}")
    log.info(f"name is:{os.getenv("HUAWEICLOUD_DOMAIN_NAME")}")

    print("Checking S3 buckets for encryption...")
    # 实际执行代码会放在这里

    print("Script execution completed")
    return 0


if __name__ == '__main__':
    sys.exit(main())