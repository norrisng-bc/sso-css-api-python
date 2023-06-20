import requests


class CssApi:
    """Wrapper for working with the CSS API."""

    @staticmethod
    def _get_token(token_url: str, client_id: str, client_secret: str):
        """Internal helper function for getting an access token."""
        return requests.post(token_url,
                             data={"grant_type": "client_credentials"},
                             auth=(client_id, client_secret)).json()['access_token']

    def __init__(self, client_id: str, client_secret: str, token_url: str = None):
        """
        Initializes the API wrapper object and gets a token.
        The CSS API hands out tokens that expire after 5 minutes, so they will have to be (manually) refreshed.
        This can be done using CssApi.refresh_token().

        :param client_id:       CSS API client ID
        :param client_secret:   CSS API client secret
        :param token_url:       Token endpoint. Defaults to the CSS token endpoint.
        """
        if token_url:
            self.token_url = token_url
        else:
            self.token_url = 'https://loginproxy.gov.bc.ca/auth/realms/standard/protocol/openid-connect/token'
        self.CSS_API_ROOT = 'https://api.loginproxy.gov.bc.ca/api/v1'
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = CssApi._get_token(self.token_url, self.client_id, self.client_secret)
        self.headers = {
            'Authorization': f'Bearer {self.token}',
        }

    def refresh_token(self):
        """Refresh the API token."""
        self.token = CssApi._get_token(self.token_url, self.client_id, self.client_secret)
        self.headers = {
            'Authorization': f'Bearer {self.token}',
        }

    def search_idir_user(self, env: str,
                      firstname: str = None,
                      lastname: str = None,
                      email: str = None,
                      guid: str = None):
        params = {
            'email': email,
            'firstName': firstname,
            'lastName': lastname,
            'guid': guid
        }
        resp = requests.get(f'{self.CSS_API_ROOT}/{env}/idir/users',
                            params={param: value for param, value in params.items() if value is not None},
                            headers=self.headers)
        resp.raise_for_status()
        data = resp.json()['data']
        if len(data) == 0:
            return None
        else:
            return data

    def search_bceid_user(self, env: str, guid: str):
        resp = requests.get(f'{self.CSS_API_ROOT}/{env}/basic-business-bceid/users?guid={guid}',
                            headers=self.headers)
        resp.raise_for_status()
        data = resp.json()['data']
        if len(data) == 0:
            return None
        else:
            return data

    def get_all_roles(self, integration_id: int, env: str):
        """Get a list of all roles in an integration.

        :param integration_id: integration id (e.g. 1234)
        :param env: integration environment (i.e. "dev", "test", or "prod")
        :returns: List of roles represented as a list of dictionaries;
                    i.e. [{'name': 'role_name', 'composite': True/False}]
        """
        resp = requests.get(f'{self.CSS_API_ROOT}/integrations/{integration_id}/{env}/roles',
                            headers=self.headers)
        resp.raise_for_status()
        return resp.json()['data']

    def get_composite_roles(self, integration_id: int, env: str):
        """Get all composite roles (i.e. ones with children roles) in an integration.

        :param integration_id: integration id (e.g. 1234)
        :param env: integration environment (i.e. "dev", "test", or "prod")
        """
        resp = requests.get(f'{self.CSS_API_ROOT}/integrations/{integration_id}/{env}/roles',
                            headers=self.headers)
        resp.raise_for_status()
        composite_roles = []
        all_roles = resp.json()['data']
        if not all_roles:
            return []
        else:
            for role in all_roles:
                if role['composite']:
                    composite_roles.append(role['name'])
            return composite_roles

    def get_child_roles(self, integration_id: int, env: str, parent_role: str):
        """Get all child roles of a given role. Returns an empty list if there are no children.

        :param integration_id: integration id (e.g. 1234)
        :param env: integration environment (i.e. "dev", "test", or "prod")
        :param parent_role: the (parent) role being checked
        """
        resp = requests.get(f'{self.CSS_API_ROOT}/integrations/{integration_id}/{env}/roles/{parent_role}/composite-roles',
                            headers=self.headers)
        resp.raise_for_status()
        all_roles = resp.json()['data']
        if not all_roles:
            return []
        else:
            return [role['name'] for role in all_roles]

    def create_role(self, integration_id: int, env: str, role: str):
        """Creates a role in the given integration/environment.

        :param integration_id: integration id (e.g. 1234)
        :param env: integration environment (i.e. "dev", "test", or "prod")
        :param role: name of role to be created
        """
        resp = requests.post(f'{self.CSS_API_ROOT}/integrations/{integration_id}/{env}/roles', json={'name': role},
                             headers=self.headers)
        resp.raise_for_status()

    def add_as_composite(self, integration_id: int, env: str, parent_role: str, child_roles: [str]):
        """Add composite roles into a role in the given integration/environment,
            assuming that all parent and child roles already exist in the integration.

        :param integration_id: integration id (e.g. 1234)
        :param env: integration environment (i.e. "dev", "test", or "prod")
        :param parent_role: Parent role to nest underneath
        :param child_roles: A list of roles to nest underneath the parent role (e.g. ['role1', 'role2', 'role3'].
                            If a child role is identical to the parent, it won't be nested, but since composites are a
                            CSS construct, any user with the parent role will appear to have all of its parent/child
                            roles as Keycloak client roles.
        """
        children = []
        # CSS doesn't allow a role to be a composite to itself (e.g. "some_role" cannot contain "some_role"),
        #   so drop them if they appear.
        for c in child_roles:
            if c != parent_role:
                children.append({'name': c})
        if children:
            resp = requests.post(f'{self.CSS_API_ROOT}/integrations/{integration_id}/{env}/roles/{parent_role}/composite-roles',
                                json=children,
                                headers=self.headers)
            resp.raise_for_status()

    def set_role(self, integration_id: int, env: str, username: str, roles: [str]):
        """
        Assign roles to a user.

        :param integration_id: integration id (e.g. 1234)
        :param env: integration environment (i.e. "dev", "test", or "prod")
        :param username: {guid}@{idp}; e.g. "fohe4m5pn8clhkxmlho33sn1r7vr7m67@idir"
        :param roles:   list of roles to add
        :return:
        """
        resp = requests.post(f'{self.CSS_API_ROOT}/integrations/{integration_id}/{env}/users/{username}/roles',
                             json=[{'name': role for role in roles}],
                             headers=self.headers)
        resp.raise_for_status()

    def remove_role(self, integration_id: int, env: str, username: str, role: str):
        """
        Unassigns role from a user.

        :param integration_id: integration id (e.g. 1234)
        :param env: integration environment (i.e. "dev", "test", or "prod")
        :param username: {guid}@{idp}; e.g. "fohe4m5pn8clhkxmlho33sn1r7vr7m67@idir"
        :param role:   role to remove
        :return:
        """
        resp = requests.delete(f'{self.CSS_API_ROOT}/integrations/{integration_id}/{env}/users/{username}/roles/{role}',
                               headers=self.headers)
        resp.raise_for_status()
