from keycloak import KeycloakAdmin


class KeycloakExtension(object):

    def __init__(self):
        self.keycloak_instance = None
        self.refresh_token = None

    def init_instance(self, server_url, realm_name, client_id,
                      client_secret=None):
        keycloak_openid = KeycloakAdmin(
            server_url=server_url,
            realm_name=realm_name,
            client_id=client_id,
            client_secret_key=client_secret)
        self.keycloak_instance = keycloak_openid

    def update_refresh_token(self, ref_token):
        self.refresh_token = ref_token

    def logout(self):
        self.keycloak_instance.logout(self.refresh_token)