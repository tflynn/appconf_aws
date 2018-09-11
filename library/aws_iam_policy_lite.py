#!/usr/bin/env python3

"""
Ansible plugin to handle basic AWS IAM Policy actions.


"""

from ansible.module_utils.basic import *

import boto3
import re
import traceback


MAX_ITEMS = 100


def delete_policy(
        client=None,
        policy_name=None,
        policy_arn=None,
        path=None):

    """
    Delete a policy specified by name or ARN. This will fail if the policy has any attachments

    Args:
        client (obj): boto3 client
        policy_name (str): Policy name. One and only one of policy name or policy ARN must be given.
        policy_arn (str): Policy ARN.
        path (str): Policy path

    Returns:
        Success (dict): Empty
        Failure (dict): Error text

    """

    if not client:
        client = boto3.client('iam')

    if not policy_name and not policy_arn:
        return {"error": "delete_policy: Either policy name or policy ARN must be specified"}

    try:
        if policy_name:
            response = list_policies_by_name(
                client=client,
                name_regex=('.*' + policy_name + '.*'),
                scope='Local',
                path_prefix=path
            )
            if 'error' in response:
                return response['error']
            else:
                policies = response['policies']
                # Pick first matching policy if multiple match
                if policies:
                    policy = policies[0]
                else:
                    return {"error": ("delete_policy: Unable to find any matching policy with name {0}"
                                      .format(policy_name))}
        else:
            response = client.get_policy(
                PolicyArn=policy_arn
            )
            if 'Policy' in response:
                policy = response['Policy']
            else:
                return {"error": ("delete_policy: Unable to find any policy with that ARN {0}"
                                  .format(policy_arn))}

        if policy['AttachmentCount'] > 0:
            return {"error": ("delete_policy: Policy {0} has attachments. Cannot delete"
                              .format(policy['PolicyNamed']))}

        client.delete_policy(
            PolicyArn=policy['Arn']
        )

        return {"policy": policy}

    except Exception as e:
        return {"error": "create_policy Error {0} {1}".format(e, traceback.format_exc())}


def create_policy(
        client=None,
        name=None,
        path=None,
        policy_document=None,
        description=None):
    """
    Create an IAM policy

    Args:
        client (obj): boto3 client
        name (str): Policy name
        path (str): Policy path
        policy_document (dict): JSON policy document
        description (str): Policy description. Defaults to 'name'

    Returns:
        Success (dict): Policy information (see boto3.create_policy)
        Failure (dict): Error text
    """

    if not client:
        client = boto3.client('iam')

    if not description:
        description = name

    try:
        response = client.create_policy(
            PolicyName=name,
            Path=path,
            PolicyDocument=policy_document,
            Description=description
        )
        if 'Policy' in response:
            return {'policy' : response['Policy']}
        else:
            return {"error" : "create_policy boto3.create_policy bad return {0}".format(response)}

    except Exception as e:
        return {"error": "create_policy Error {0} {1}".format(e, traceback.format_exc())}


def list_policies_by_name(
        client=None,
        name_regex=None,
        scope='Local',
        path_prefix='/',
        marker=None,
        max_items=MAX_ITEMS):
    """
    List all policies matching a given name (fragment)

    Args:
        client (obj): boto3 client
        name_regex (str): String containing a regex to test for the policy name
        scope (str): Scope 'All' | 'AWS' | 'Local'. Defaults to 'Local'
        path_prefix (str): Policy path. Defaults to '/'.
        marker (str): Pagination marker. Defaults to 'None'.
        max_items (int): Max items in any one (paginated) call. Defaults to 100.

    Returns:

    """

    if not client:
        client = boto3.client('iam')

    if not name_regex:
        return {"error": "Invalid argument. No name regex specified."}

    try:
        name_regex = re.compile(name_regex)

        kwargs = dict(
            Scope=scope,
            OnlyAttached=False,
            PathPrefix=path_prefix,
            MaxItems=max_items
        )
        if marker:
            kwargs.update(dict(Marker=marker))

        response = client.list_policies(**kwargs)

        all_policies = []

        if 'Policies' in response:
            matching_policies = [policy for policy in response['Policies'] if name_regex.match(policy['PolicyName'])]
            all_policies.extend(matching_policies)

        if response['IsTruncated']:
            kwargs = dict(
                client=client,
                name_regex=name_regex,
                scope=scope,
                path_prefix = path_prefix,
                max_items=max_items
            )
            if marker:
                kwargs.update(dict(marker=marker))
            matching_policies = list_policies_by_name(**kwargs)
            all_policies.extend(matching_policies)

        return {"policies": all_policies}

    except Exception as e:
        return {"error": "Error {0} {1}".format(e, traceback.format_exc())}


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

    client = boto3.client('iam')

    if state == 'present':

        try:
            response = list_policies_by_name(
                client=client,
                name_regex=('.*' + policy_name + '.*'),
                scope='Local',
                path_prefix=path
            )

            if 'error' in response:
                error = response['error']
            else:
                policies = response['policies']
                # Pick first matching policy if multiple match
                if policies:
                    policy = policies[0]
                else:
                    response = create_policy(client, policy_name, path, policy_document, description)
                    if 'error' in response:
                        error = response['error']
                    else:
                        changed = True
                        policy = response['policy']

        except Exception as e:
            module.fail_json(msg='policy action failed: {0 {1}'.format(e,traceback.format_exc()))

    elif state == 'absent':
        response = delete_policy(client, policyName=policy_name, policy_arn=policy_arn, path=path)
        if 'error' in response:
            error.update(response['error'])
        else:
            changed = True
            policy = response['policy']

    else:
        error = {"error": "state must be either 'present' or 'absent'"}

    if error:
        module.fail_json(msg='policy action failed: {0}'.format(error))
        #module.fail_json(msg='policy action failed: {0}'.format(error['error']))

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

    if not isinstance(policy_document, str):
        try:
            policy_document = json.dumps(policy_document)
        except Exception as e:
            module.fail_json(
                msg='Failed to convert the policy into valid JSON: {0} {1}'.format(e,traceback.format_exc()))

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
