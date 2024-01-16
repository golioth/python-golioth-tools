import golioth
import pytest
from fixtures.rand_name import NAME_PREFIX, get_random_name

@pytest.fixture(scope="module")
async def tag(project):
    tag_name = get_random_name()
    tag = await project.tags.create(tag_name)
    yield tag

    await project.tags.delete(tag.id)


@pytest.fixture(scope="module")
async def tag_to_delete(project):
    tag_name = get_random_name()
    tag = await project.tags.create(tag_name)
    yield tag

    try:
        await project.tags.delete(tag.id)
    except:
        pass


@pytest.fixture(scope="module")
async def tagname_to_create(project):
    tag_name = get_random_name()
    yield tag_name

    try:
        tag_id = await project.tags.get_id(tag_name)
        await project.tags.delete(tag_id)
    except:
        pass
