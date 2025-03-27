from huaweicloud_common import BaseTest


class IamTest(BaseTest):
    def test_alarm_query(self):
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
