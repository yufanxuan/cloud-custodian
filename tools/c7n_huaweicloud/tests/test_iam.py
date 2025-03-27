# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import os

from huaweicloud_common import BaseTest

HUAWEICLOUD_CONFIG_GLOBAL = {
    'HUAWEI_DEFAULT_REGION': 'cn-north-4',
    'HUAWEI_ACCESS_KEY_ID': 'access_key_id',
    'HUAWEI_SECRET_ACCESS_KEY': 'secret_access_key',
    'HUAWEI_PROJECT_ID': 'cn-north-4',
}


def init_huaweicloud_config_global():
    for k, v in HUAWEICLOUD_CONFIG_GLOBAL.items():
        os.environ[k] = v

class IamTest(BaseTest):
    def test_alarm_query(self):
        init_huaweicloud_config_global()
        factory = self.replay_flight_data('iam_user_delete')
        p = self.load_policy({
            'name': 'delete-user',
            'resource': 'huaweicloud.iam-user',
            "filters": [{
                "type": "access-key",
                "key": "status",
                "value": "inactive"
            }],
            "actions": ["delete"]
        },
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 0)
