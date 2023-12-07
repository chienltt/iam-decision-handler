from flask_restx import Namespace

from src.api.admin.resources.policy_enforcer import PolicyEnforcer
from src.api.admin.resources.test import LoadDataResource
from src.api.admin.resources.decision_handler import DecisionHandler

_ROUTES = [
    {
        'name': 'Test',
        'description': 'Test',
        'path': '/refresh_data',
        'resources': [
            (LoadDataResource, '/')
        ]
    },
    {
        'name': 'Policy enforcer',
        'description': 'Policy enforcer',
        'path': '/policy-enforcer',
        'resources': [
            (PolicyEnforcer, '/<client_id>')
        ]
    },
    {
        'name': 'Decision Handler',
        'description': 'Decision Handler',
        'path': '/decision-handler',
        'resources': [
            (DecisionHandler, '/<client_id>')
        ]
    }
]


def _add_namespaces():
    """Add namespaces and resources for api instance of the version 1.0."""
    for ns in _ROUTES:
        resources = ns.pop('resources', [])
        api_ns = Namespace(**ns)
        for rs in resources:
            api_ns.add_resource(*rs)
        yield api_ns


ADMIN_API_ROUTES = _add_namespaces()