import requests

from src.config import Config
from src.extension import keycloak_extension, resource_setting_storage
from src.repository.base import fetch_data


def get_current_resources():
    sql = "select ID from RESOURCE_SERVER"
    data = fetch_data(sql)
    return data


def load_resources_setting(list_resource_ids):
    for id in list_resource_ids:
        resource_setting_url = Config.KEYCLOAK_URL + (
                '/admin/realms/school_management/clients/' +
                id + '/authz/resource-server/settings')
        headers = {
            "Authorization": "Bearer " +
                             keycloak_extension.keycloak_instance.token[
                                 'access_token'],
            "Content-Type": "application/json",
        }
        response = requests.get(resource_setting_url, headers=headers)
        if response.status_code == 200 and response.json():
            resource_setting_storage.set(id, response.json())
