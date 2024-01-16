import golioth
import pytest
from fixtures.rand_name import NAME_PREFIX, get_random_name

@pytest.fixture(scope="module")
async def blueprint(project):
    blueprint_name = get_random_name()
    blueprint = await project.blueprints.create(blueprint_name)
    yield blueprint

    await project.blueprints.delete(blueprint.id)


@pytest.fixture(scope="module")
async def blueprint_to_delete(project):
    blueprint_name = get_random_name()
    blueprint = await project.blueprints.create(blueprint_name)
    yield blueprint

    try:
        await project.blueprints.delete(blueprint.id)
    except:
        pass


@pytest.fixture(scope="module")
async def blueprintname_to_create(project):
    blueprint_name = get_random_name()
    yield blueprint_name

    try:
        blueprint_id = await project.blueprints.get_id(blueprint_name)
        await project.blueprints.delete(blueprint_id)
    except:
        pass
