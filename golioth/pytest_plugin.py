import os
import pytest
from golioth import Client

def pytest_addoption(parser):
    parser.addoption("--api-key", type=str,
                     help="Golioth API key")
    parser.addoption("--device-name", type=str,
                     help="Golioth device name")


@pytest.fixture(scope='session')
def anyio_backend():
    return 'trio'

@pytest.fixture(scope="session")
def api_key(request):
    if request.config.getoption("--api-key") is not None:
        return request.config.getoption("--api-key")
    else:
        return os.environ['GOLIOTH_API_KEY']

@pytest.fixture(scope="session")
def device_name(request):
    if request.config.getoption("--device-name") is not None:
        return request.config.getoption("--device-name")
    else:
        return os.environ['GOLIOTH_DEVICE_NAME']

@pytest.fixture(scope="module")
async def project(api_key):
    client = Client(api_url = "https://api.golioth.dev",
                    api_key = api_key)
    project = (await client.get_projects())[0]

    return project

@pytest.fixture(scope="module")
async def device(project, device_name):
    device = await project.device_by_name(device_name)

    return device
