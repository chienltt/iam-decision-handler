from flask import request
from flask_restx import Resource
from src.extension import api
from src.repository import (get_current_resources, load_resources_setting,
                            get_current_user_role_mappings,
                            load_user_role_mappings, load_public_keys)


class LoadDataResource(Resource):

    @api.doc(params={'ten': 'ten'})
    def get(self):
        resources = get_current_resources()
        list_resource_id = set()
        for resource in resources:
            list_resource_id.add(resource[0])
        load_resources_setting(list_resource_id)
        user_role_data = get_current_user_role_mappings()
        load_user_role_mappings(user_role_data)
        load_public_keys()

        return {'status': 'ok', 'result': 'ok'}, 200
