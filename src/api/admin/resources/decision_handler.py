import json

from flask import request, make_response, current_app
from flask_restx import Resource
import jwt

from src.extension import api, policy_enforcer_storage, \
    resource_setting_storage, public_keys_storage, user_role_storage
from src.helper.helper import match_path, is_subarray, convert_string_to_set, \
    verify_token_signature, verify_valid_token


class DecisionHandler(Resource):

    def verify_token(self):
        authorization_header = request.headers.get('Authorization')

        if authorization_header and authorization_header.startswith('Bearer '):
            access_token = authorization_header[len('Bearer '):]
            try:
                # Decode the JWT token
                token_header = jwt.get_unverified_header(access_token)
                public_key_data = public_keys_storage.get(token_header['kid'])
                decoded_token = verify_token_signature(access_token,
                                                       public_key_data)
                payload = request.get_json()
                is_valid_token = verify_valid_token(access_token, payload[
                    'client_name_id'], payload['client_secret'])
                if not is_valid_token:
                    return None
                user_id = decoded_token['sub']
                return user_id
            except jwt.ExpiredSignatureError as e:
                print("Token has expired", e)
                make_response("unauthorized", 401)
            except jwt.InvalidTokenError as e:
                print("Token is invalid", e)
                make_response("unauthorized", 401)
        else:
            make_response("unauthorized", 401)

    def verify_access(self, user_id, client_id):
        policy_enforcer_data = policy_enforcer_storage.get(client_id)
        if policy_enforcer_data is None:
            make_response("invalid_client", 400)

        payload = request.get_json()
        enforcement_mode = policy_enforcer_data.get('enforcement-mode',
                                                    "ENFORCING")
        uri = ""
        scopes = []
        scopes_enforcement_mode = ""
        if policy_enforcer_data.get('paths') is not None:
            for path in policy_enforcer_data['paths']:
                if match_path(payload['endpoint'], path['path']):
                    uri = path['path']
                    for method in path['methods']:
                        if method['method'] == payload['method']:
                            scopes = method['scopes']
                            scopes_enforcement_mode = method.get(
                                'scopes_enforcement_mode', "ANY")
        if len(scopes) == 0:
            if enforcement_mode == "ENFORCING":
                return False
            else:
                return True
        resources_setting = resource_setting_storage.get(client_id)
        if resources_setting is None:
            return False
        for re in resources_setting["resources"]:
            for _uri in re['uris']:
                if match_path(uri, _uri):
                    if re.get('scopes') is not None:
                        resource_scopes = [scope["name"] for scope in
                                           re["scopes"]]
                        if not is_subarray(scopes, resource_scopes):
                            return False
        role_policies_require = set()
        for scope in scopes:
            for policy in resources_setting["policies"]:
                if policy["type"] == "scope":
                    if scope in policy['config']['scopes']:
                        apply_policies = convert_string_to_set(policy['config'][
                                                                   'applyPolicies'])
                        role_policies_require.update(apply_policies)
        roles_require = set()
        for role_policy in role_policies_require:
            for policy in resources_setting["policies"]:
                if role_policy == policy['name']:
                    roles = json.loads(policy['config']['roles'])
                    for role in roles:
                        roles_require.add(role['id'])
        user_role = user_role_storage.get(user_id)
        roles_require = list(roles_require)
        if scopes_enforcement_mode == "ALL":
            if is_subarray(roles_require, user_role):
                return True
            else:
                return False

        if scopes_enforcement_mode == "ANY":
            for role_require in roles_require:
                if role_require in user_role:
                    return True
            return False
        else:
            return True

    @api.doc(params={'ten': 'ten'})
    def post(self, client_id):
        user_id = self.verify_token()
        if user_id is None:
            return {'result': False}, 200
        is_access = self.verify_access(user_id, client_id)
        if is_access:
            return {'result': True}, 200
        else:
            return {'result': False}, 200