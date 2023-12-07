from flask import request
from flask_restx import Resource
from src.extension import api, policy_enforcer_storage


class PolicyEnforcer(Resource):

    @api.doc(params={'ten': 'ten'})
    def get(self, client_id):
        data = policy_enforcer_storage.get(client_id)
        return data, 200

    @api.doc(params={'ten': 'ten'})
    def post(self, client_id):
        policy_enforcer_data = request.get_json()
        policy_enforcer_storage.set(client_id, policy_enforcer_data)
        return {'status': 'success'}, 200
