import requests

from src.config import Config
from src.extension import public_keys_storage, keycloak_extension


def load_public_keys():
    public_keys_url = Config.KEYCLOAK_URL + "/admin/realms/school_management/keys"
    headers = {
        "Authorization": "Bearer " +
                         keycloak_extension.keycloak_instance.token[
                             'access_token'],
        "Content-Type": "application/json",
    }
    response = requests.get(public_keys_url, headers=headers)

    if response.status_code == 200:
        response = response.json()
        for key in response['keys']:
            if key.get('kid') is not None and key.get('publicKey') is not None:
                public_keys_storage.set(key.get('kid'), key)
