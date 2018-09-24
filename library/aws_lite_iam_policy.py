#!/usr/bin/env python3

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
Ansible plugin to handle basic AWS IAM Policy actions.


"""

from ansible.module_utils.basic import *
from ansible.module_utils.basic import AnsibleModule

import traceback

import json

from aws_idem.iam import policy as policy_m


def policy_action(module,
                  state=None,
                  policy_name=None,
                  policy_arn=None,
                  policy_document=None,
                  path=None,
                  description=None):
    """
    Execute the actions needed to bring the policy into the specified state.

    Args:
        module (obj): Ansible module
        state (str): Ansible state - 'present' | 'absent'
        policy_name (str): Policy name. One and only one of policy name or policy ARN must be given.
        policy_arn (str): Policy ARN. One and only one of policy name or policy ARN must be given.
        policy_document(dict): JSON policy document
        path (str): Policy path
        description (str): Policy description. Defaults to 'policy_name'

    Returns:
        Success:
            (bool) changed, (dict) policy object (see boto3.get_policy docs)
        Failure:
            Invokes  module.fail_json with suitable text at point of error
    """

    changed = False
    policy = None
    error = {}

    if state == 'present':
        try:
            if isinstance(policy_document, dict):
                policy_document = json.dumps(policy_document)

            response = policy_m.create_policy(
                policy_name=policy_name,
                path=path,
                policy_document=policy_document,
                description=description)

            if 'error' in response:
                error = response['error']
            else:
                if response['state'] == 'New':
                    changed = True
                policy = response['policy']

        except Exception as e:
            module.fail_json(msg='policy action {0} failed: {1} {2}'.format('present', e,traceback.format_exc()))

    elif state == 'absent':
        try:
            response = policy_m.delete_policy(
                policy_name=policy_name,
                path=path)

            if 'error' in response:
                error = response['error']
            else:
                changed = True
                policy = response['policy']

        except Exception as e:
            module.fail_json(msg='policy action {0} failed: {1} {2}'.format('absent', e,traceback.format_exc()))

    else:
        error = {"error": "state must be either 'present' or 'absent'"}

    if error:
        module.fail_json(msg='policy action failed: {0}'.format(error))

    return changed, policy


def main():
    """
    Entry point for Ansible plugin to handle basic AWS IAM Policy actions.

    Returns:
        Success:
            (bool) changed, (dict) policy object (see boto3.get_policy docs)
        Failure:
            Invokes  module.fail_json with suitable text at point of error
    """

    argument_spec = {}
    argument_spec.update(dict(
        state=dict(
            default=None, required=True, choices=['present', 'absent']),
        policy_name=dict(default=None, required=False),
        policy_arn=dict(default=None, required=False),
        policy_document=dict(default=None, required=False),
        path=dict(default='/', required=False),
        description=dict(default=None, required=False),
    ))

    module = AnsibleModule(argument_spec=argument_spec,)

    state = module.params.get('state')
    policy_name = module.params.get('policy_name')
    policy_arn = module.params.get('policy_arn')
    policy_document = module.params.get('policy_document')
    path = module.params.get('path')
    description = module.params.get('description')

    changed, policy = policy_action(module,
                                    state=state,
                                    policy_name=policy_name,
                                    policy_arn=policy_arn,
                                    policy_document=policy_document,
                                    path=path,
                                    description=description)

    module.exit_json(changed=changed, policy=policy)


if __name__ == '__main__':
    main()
