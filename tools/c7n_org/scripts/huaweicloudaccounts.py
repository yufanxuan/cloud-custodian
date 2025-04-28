# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import click
import jmespath
from huaweicloudsdkorganizations.v1 import ListAccountsRequest

from c7n.utils import yaml_dump
from tools.c7n_huaweicloud.c7n_huaweicloud.client import Session

NAME_TEMPLATE = "{name}"


def get_next_page_params(response=None):
    if not response:
        return None
    page_info = jmespath.search("page_info", response)
    if not page_info:
        return None
    return page_info.get("next_marker")

@click.command()
@click.option(
    '-f', '--output', type=click.File('w'),
    help="File to store the generated config (default stdout)")
@click.option(
    '-s', '--state', multiple=True, type=click.Choice(
        ['Enabled', 'Warned', 'PastDue', 'Disabled', 'Deleted']),
    default=('Enabled',),
    help="File to store the generated config (default stdout)")
@click.option(
    '--name',
    default=NAME_TEMPLATE,
    help="Name template for subscriptions in the config, defaults to %s" % NAME_TEMPLATE)
def main(output, agency_name, duration_seconds):
    """
    Generate a c7n-org huawei cloud accounts config file
    """
    if not duration_seconds:
        duration_seconds = 900
    if not agency_name:
        agency_name = "custodian_agency"

    accounts = []
    marker = None
    while True:
        client = Session().client("org-account")
        request = ListAccountsRequest(limit=1000, marker=marker)
        response = client.list_accounts(request)
        marker = get_next_page_params(response)
        for account in response.accounts:
            accounts.append(account.id)
        if not marker:
            break

    results = []
    for account in accounts:
        acc_info = {
            'name': account['name'],
            'domain_id': account['id'],
            'agency_urn': f"iam::{account['id']}:agency:{agency_name}",
            'duration_seconds': duration_seconds

        }
        results.append(acc_info)

    print(yaml_dump({'accounts': results}), file=output)


if __name__ == '__main__':
    main()
