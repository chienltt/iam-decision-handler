import json

from src.extension import user_role_storage
from src.repository.base import fetch_data


def get_current_user_role_mappings():
    sql = ("select USER_ROLE_MAPPING.USER_ID, KEYCLOAK_ROLE.NAME from "
           "USER_ROLE_MAPPING inner join KEYCLOAK_ROLE on USER_ROLE_MAPPING.ROLE_ID = KEYCLOAK_ROLE.ID")
    data = fetch_data(sql)
    return data


def load_user_role_mappings(list_user_role_mapping):
    user_role_mapping_dict = {}
    for (user_id, role_name) in list_user_role_mapping:
        if user_role_mapping_dict.get(user_id) is not None:
            user_role_mapping_dict[user_id].add(role_name)
        else:
            user_role_mapping_dict[user_id] = {role_name}

    for user_id in user_role_mapping_dict:
        print(user_id, ':', user_role_mapping_dict[user_id])
        role_mapping_data = json.dumps(list(user_role_mapping_dict[user_id]))
        user_role_storage.set(user_id, role_mapping_data)
