import functools
import logging
import os

from huaweicloudsdkcore.auth.credentials import GlobalCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkiam.v3 import UpdateLoginProtectRequest, UpdateLoginProjectReq, UpdateLoginProject, IamClient as IamClientV3
from huaweicloudsdkiam.v3.region import iam_region as iam_region_v3
from huaweicloudsdkiam.v5 import ListAccessKeysV5Request, ListAttachedUserPoliciesV5Request, DetachUserPolicyV5Request, \
    DetachUserPolicyReqBody, DeleteUserV5Request, AddUserToGroupV5Request, AddUserToGroupReqBody, \
    RemoveUserFromGroupV5Request, RemoveUserFromGroupReqBody, DeletePolicyV5Request, DeleteAccessKeyV5Request

from c7n.filters import ValueFilter
from c7n.utils import type_schema, chunks, jmespath_search
from tools.c7n_huaweicloud.c7n_huaweicloud.actions import HuaweiCloudBaseAction
from tools.c7n_huaweicloud.c7n_huaweicloud.pagination import Pagination
from tools.c7n_huaweicloud.c7n_huaweicloud.provider import resources
from tools.c7n_huaweicloud.c7n_huaweicloud.query import QueryResourceManager, TypeInfo

log = logging.getLogger("custodian.huaweicloud.resources.iam")

DEFAULT_LIMIT_SIZE = 100

class IAMMarkerPagination(Pagination):
    def get_first_page_params(self):
        return {'limit': DEFAULT_LIMIT_SIZE}
    
    def get_next_page_params(self, response):
        page_info = jmespath_search('page_info', eval(
            str(response)
            .replace('null', 'None')
            .replace('true', 'True')
            .replace('false', 'False')))

        if not page_info:
            return None
        next_marker = page_info.get('next_marker')
        if not next_marker:
            return None
        return {'limit': DEFAULT_LIMIT_SIZE, 'marker': next_marker}


@resources.register('iam-user')
class User(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'iam'
        pagination = IAMMarkerPagination()
        enum_spec = ("list_users_v5", 'users', pagination)
        id = 'user_id'
        tag = True

@User.action_registry.register('delete')
class UserDelete(HuaweiCloudBaseAction):
    """Delete a user.

    :Example:

    .. code-block:: yaml

        policies:
          - name: delete-user
            resource: huaweicloud.iam-user
            filters:
              - type: access-key
                key: status
                value: active
              - type: access-key
                key: created_at
                value_type: age
                value: 90
                op: gt
            actions:
              - delete
    """

    schema = type_schema('delete')

    def perform_action(self, resource):
        client = self.manager.get_client()
        try:
            request = ListAttachedUserPoliciesV5Request(
                user_id=resource["id"], limit=200)
            response = client.list_attached_user_policies_v5(request)
            policy_ids = [policy.policy_id for policy in response.attached_policies]

            for policy_id in policy_ids:
                try:
                    request = DetachUserPolicyV5Request(policy_id=policy_id)
                    request.body = DetachUserPolicyReqBody(user_id=resource["id"])
                    client.detach_user_policy_v5(request)
                    print(f"Successfully detached policy: {policy_id}")
                except exceptions.ClientRequestException as e:
                    print(f"Failed to detach policy {policy_id}: {e.error_msg}")

            request = DeleteUserV5Request(user_id=resource["id"])
            response = client.delete_user_v5(request)
            if response.status_code == 204:
                print(f"Successfully deleted user: {resource['id']}")
            else:
                print(f"Failed to delete user: {resource['id']}. Status code: {response.status_code}")

        except exceptions.ClientRequestException as e:
            print(e.status_code)
            print(e.request_id)
            print(e.error_code)
            print(e.error_msg)
        except Exception as e:
            print(f"Unexpected error: {e}")

@User.action_registry.register('set-group')
class SetGroup(HuaweiCloudBaseAction):
    """Delete a user.

    :Example:

    .. code-block:: yaml

        policies:
          - name: set-group
            resource: huaweicloud.iam-user
            filters:
              - type: access-key
                key: status
                value: active
              - type: access-key
                key: created_at
                value_type: age
                value: 90
                op: gt
            actions:
              - type: set-groups
                state: remove
                group_id: aba123xxxxxxxxxxxd1ss1fd
    """

    schema = type_schema(
        'set-group',
        state={'enum': ['add', 'remove']},
        group_id={'type': 'string'},
        required=['state', 'group_id']
    )

    def perform_action(self, resource):
        group_id = self.data.get('group_id')
        user_id = resource["id"]
        state = self.data['state']
        client = self.manager.get_client()
        try:
            if state == 'add':
                request = AddUserToGroupV5Request(group_id=group_id)
                request.body = AddUserToGroupReqBody(user_id=user_id)
                response = client.add_user_to_group_v5(request)
                print(response)
            elif state == 'remove':
                request = RemoveUserFromGroupV5Request(group_id=group_id)
                request.body = RemoveUserFromGroupReqBody(user_id=user_id)
                response = client.remove_user_from_group_v5(request)
                print(response)
        except exceptions.ClientRequestException as e:
            print(e.status_code)
            print(e.request_id)
            print(e.error_code)
            print(e.error_msg)
        except Exception as e:
            print(f"Unexpected error: {e}")

@User.action_registry.register('remove-access-key')
class UserRemoveAccessKey(HuaweiCloudBaseAction):
    """Delete a user.

    :Example:

    .. code-block:: yaml

        policies:
          - name: UserRemoveAccessKey
            resource: huaweicloud.iam-user
            filters:
              - type: access-key
                key: status
                value: active
              - type: access-key
                key: created_at
                value_type: age
                value: 90
                op: gt
            actions:
              - type: remove-access-key
                disable: true
    """

    schema = type_schema(
        'remove-access-key',
        disable={'type': 'boolean'})

    def perform_action(self, resource):
        client = self.manager.get_client()
        try:
            for key in resource["c7n:matched-keys"]:
                request = DeleteAccessKeyV5Request(
                    user_id=resource["id"],
                    access_key_id=key.access_key_id)
                response = client.delete_access_key_v5(request)
                print(response)
        except exceptions.ClientRequestException as e:
            print(e.status_code)
            print(e.request_id)
            print(e.error_code)
            print(e.error_msg)
        except Exception as e:
            print(f"Unexpected error: {e}")

@User.action_registry.register('set-login-protect')
class SetLoginProtect(HuaweiCloudBaseAction):
    """Set IAMUser Login Protect.

    :Example:

    .. code-block:: yaml

        policies:
          - name: set-user-login-protect
            resource: huaweicloud.iam-user
            filters:
              - type: access-key
                key: status
                value: active
              - type: access-key
                key: created_at
                value_type: age
                value: 90
                op: gt
            actions:
              - type: set-login-protect
                enabled: true
                verification_method: vmfa
    """

    schema = type_schema(
        'set-login-protect',
        enabled={'type': 'boolean'},
        verification_method={'enum': ['vmfa', 'sms', 'email']},
    )

    def perform_action(self, resource):
        globalCredentials = GlobalCredentials(os.getenv('HUAWEI_ACCESS_KEY_ID'), os.getenv('HUAWEI_SECRET_ACCESS_KEY'))
        client = IamClientV3.new_builder() \
            .with_credentials(globalCredentials) \
            .with_region(iam_region_v3.IamRegion.value_of(os.getenv('HUAWEI_DEFAULT_REGION'))) \
            .build()
        try:
            request = UpdateLoginProtectRequest(user_id=resource["id"])

            loginProtectBody = UpdateLoginProject(
                enabled=self.data.get('enabled'),
                verification_method=self.data.get('verification_method')
            )
            request.body = UpdateLoginProjectReq(login_protect=loginProtectBody)

            response = client.update_login_protect(request)
            print(response)
        except exceptions.ClientRequestException as e:
            print(e.status_code)
            print(e.request_id)
            print(e.error_code)
            print(e.error_msg)

"""------------------------------------filter---------------------------------------"""

@User.filter_registry.register('access-key')
class UserAccessKey(ValueFilter):
    """Filter IAM users based on access-key values

    By default multiple uses of this filter will match
    on any user key satisfying either filter. To find
    specific keys that match multiple access-key filters,
    use `match-operator: and`

    :example:

    .. code-block:: yaml

        policies:
          - name: iam-users-with-active-keys-or-created_at
            resource: huaweicloud.iam-user
            filters:
              - or:
                - type: access-key
                  key: status
                  value: active
                - type: access-key
                  key: created_at
                  value_type: age
                  value: 90
                  op: gt
    """

    schema = type_schema(
        'access-key',
        rinherit=ValueFilter.schema,
        **{'match-operator': {'enum': ['and', 'or']}})
    schema_alias = False
    permissions = ('iam:ListAccessKeys',)
    annotation_key = 'access_keys'
    matched_annotation_key = 'c7n:matched-keys'
    annotate = False

    def get_user_keys(self, client, user_set):
        for u in user_set:
            try:
                response = client.list_access_keys_v5(ListAccessKeysV5Request(user_id=u['user_id']))
                access_keys = response.access_keys
                u[self.annotation_key] = [
                    {
                        'access_key_id': key.access_key_id,
                        'status': key.status,
                        'created_at': key.created_at.isoformat()
                    }
                    for key in access_keys
                ]
            except Exception as e:
                log.error(f"Failed to list access keys for user {u['user_id']}: {e}")
                u[self.annotation_key] = []

    def process(self, resources, event=None):
        client = self.manager.get_client()
        with self.executor_factory(max_workers=2) as w:
            augment_set = [r for r in resources if self.annotation_key not in r]
            self.log.debug(
                "Querying %d users' api keys" % len(augment_set))
            list(w.map(
                functools.partial(self.get_user_keys, client),
                chunks(augment_set, 50)))

        matched = []
        for r in resources:
            keys = r[self.annotation_key]
            k_matched = []
            for k in keys:
                if self.match(k):
                    k_matched.append(k)
            for k in k_matched:
                k['c7n:match-type'] = 'access'
            self.merge_annotation(r, self.matched_annotation_key, k_matched)
            if k_matched:
                matched.append(r)

        return matched