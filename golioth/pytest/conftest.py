import pytest

@pytest.fixture(scope='session')
def anyio_backend():
    return 'trio'

pytest_plugins = [
    "fixtures.blueprints",
    "fixtures.cohorts",
    "fixtures.deployments",
    "fixtures.packages",
    "fixtures.tags",
]
