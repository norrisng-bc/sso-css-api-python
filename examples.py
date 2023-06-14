from sso_css import CssApi


CSS_API_CREDENTIALS = {
      "tokenUrl": "https://loginproxy.gov.bc.ca/auth/realms/standard/protocol/openid-connect/token",
      "clientId": "service-account-team-####-####",
      "clientSecret": "client-secret-here"
    }


def copy_roles_across_integrations():
    """
    Copy roles from one integration to another
    """
    SOURCE_INTEGRATION = 1234            # Integration to copy from
    TARGET_INTEGRATION = 5678      # Integration to copy to

    api = CssApi(CSS_API_CREDENTIALS["clientId"], CSS_API_CREDENTIALS["clientSecret"])
    all_roles = api.get_all_roles(SOURCE_INTEGRATION, 'test')

    # First pass: create all roles (we'll deal with nesting the composite roles on the second pass)
    for role in all_roles:
        api.create_role(TARGET_INTEGRATION, 'test', role['name'])

    # Second pass: get all composite roles, find their children, and assign them to the parent
    all_composite_roles = api.get_composite_roles(SOURCE_INTEGRATION, 'test')
    for parent_role in all_composite_roles:
        children = api.get_child_roles(SOURCE_INTEGRATION, 'test', parent_role)
        api.add_as_composite(TARGET_INTEGRATION, 'test', parent_role, children)
