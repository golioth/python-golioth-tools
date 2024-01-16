import pytest
from golioth import Tag

pytestmark = pytest.mark.anyio

async def test_get_all(project, tag):
    all_tags = await project.tags.get_all()
    for t in all_tags:
        if t.id == tag.id:
            assert t.name == tag.name
            return

    assert False, "Tag not found"


async def test_get(project, tag):
    found_tag = await project.tags.get(tag.id)
    assert tag.name == found_tag.name


async def test_get_id(project, tag):
    tag_id = await project.tags.get_id(tag.name)
    assert tag.id == tag_id


async def test_delete(project, tag_to_delete):
    new_tag = tag_to_delete
    assert type(new_tag) == Tag

    await project.tags.delete(new_tag.id)

    with pytest.raises(Exception):
        await project.tags.delete(new_tag.id)


async def test_create(project, tagname_to_create):
    new_tag = await project.tags.create(tagname_to_create)
    assert new_tag.name == tagname_to_create
