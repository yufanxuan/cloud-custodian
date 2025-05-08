# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import click
import jmespath
from huaweicloudsdkorganizations.v1 import ListAccountsRequest

from c7n.utils import yaml_dump
from c7n_huaweicloud.client import Session


def get_next_page_params(response=None):
    if not response:
        return None
    page_info = response.page_info
    print(f"page_info:{page_info}")
    if not page_info:
        return None
    next_marker = page_info.next_marker
    if not next_marker:
        return None
    return next_marker


@click.command()
@click.option(
    '-f', '--output',
    type=click.File('w'), default='accounts.yml',
    help="File to store the generated config. default: ./accounts.yml")
@click.option(
    '-a', '--agency_name',
    type=str, default='custodian_agency',
    help="trust agency name. default:custodian_agency")
@click.option(
'-n', '--name',
    multiple=True, type=str,
    help="The account name specified for the query")
@click.option(
'-o', '--ou_ids',
    multiple=True, type=str,
    help="The Organizational Unit id specified for the query")
@click.option(
'-s', '--status',
    multiple=True, type=str,
    help="The account status specified for the query")
@click.option(
    '-d', '--duration_seconds',
    default=900, type=int,
    help="assume session duration second. default:900")
@click.option(
'-r', '--regions',
    multiple=True, type=str, default=('cn-north-4',),
    help="huaweicloud region for executing policy. default:cn-north-4")
def main(output, agency_name, name, ou_ids, status, duration_seconds, regions):
    """
    Generate a c7n-org huawei cloud accounts config file
    """
    options = {"region": 'cn-north-4'}
    accounts = []
    marker = None
    session = Session(options)
    client = session.client("org-account")
    print(f"name:{name}")
    print(f"ou_id:{ou_ids}")
    ou_id_len = len(ou_ids)
    while True:
        ou_id_len = ou_id_len - 1
        print(f"ou_id_len:{ou_id_len}")
        while True:
            request = ListAccountsRequest(limit=1000, marker=marker)
            response = client.list_accounts(request)
            print(f"response{response}")
            marker = get_next_page_params(response)
            print(f"marker{marker}")
            for account in response.accounts:
                if name and account.name not in name:
                    continue
                if status and account.status not in status:
                    continue
                accounts.append(account)

            if not marker:
                break
        if ou_id_len <= 0:
            break
    print(f"3{accounts}")
    results = []
    for account in accounts:
        acc_info = {
            'name': account.name,
            'domain_id': account.id,
            'agency_urn': f"iam::{account.id}:agency:{agency_name}",
            'duration_seconds': duration_seconds,
            'regions': regions
        }
        results.append(acc_info)

    print(yaml_dump({'domains': results}), file=output)


if __name__ == '__main__':
    main()
