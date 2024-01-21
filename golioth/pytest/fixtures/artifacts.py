import golioth
import pytest
from pathlib import Path
from os import remove
from fixtures.rand_name import get_random_name

ARTIFACT_TEST_VERSION = '255.99.1'
ARTIFACT_TEST_PACKAGE = 'pytest'
ARTIFACT_DELETE_VERSION = '255.99.87'
ARTIFACT_CREATE_VERSION = '255.109.42'

def generate_fake_bin(unique_str = None):
    if unique_str == None:
        unique_str = get_random_name()
    fake_binary = f'artifact-{unique_str}.bin'
    with open(fake_binary, 'wb') as f:
        f.write(bytes(fake_binary, 'utf8'))
    return fake_binary


@pytest.fixture(scope="module")
async def artifact(project, blueprint):
    fake_binary = generate_fake_bin()
    artifact = await project.artifacts.upload(Path(fake_binary), ARTIFACT_TEST_VERSION, ARTIFACT_TEST_PACKAGE, blueprint.id)
    yield artifact

    remove(fake_binary)
    await project.artifacts.delete(artifact.id)



@pytest.fixture(scope="module")
async def artifact_to_delete(project, blueprint):
    fake_binary = generate_fake_bin()
    artifact = await project.artifacts.upload(Path(fake_binary), ARTIFACT_DELETE_VERSION, ARTIFACT_TEST_PACKAGE, blueprint.id)
    yield artifact

    remove(fake_binary)
    try:
        await project.artifacts.delete(artifact.id)
    except:
        pass


@pytest.fixture(scope="module")
async def new_artifact_info(project, blueprint):
    fake_binary = generate_fake_bin()
    artifact = {'binary': fake_binary,
                'version': ARTIFACT_CREATE_VERSION,
                'package': ARTIFACT_TEST_PACKAGE,
                'blueprint_id': blueprint.id}

    yield artifact

    remove(fake_binary)

    try:
        artifacts = await project.artifacts.get_all()
        for a in artifacts:
            if (a.package == artifact['package'] and
                a.version == artifact['version'] and
                a.blueprint == artifact['blueprint_id']):

                await project.artifacts.delete(a.id)
                break

    except:
        pass
