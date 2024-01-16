import pytest
from golioth import Blueprint

pytestmark = pytest.mark.anyio

async def test_get_all(project, blueprint):
    all_blueprints = await project.blueprints.get_all()
    for b in all_blueprints:
        if b.id == blueprint.id:
            assert b.name == blueprint.name
            assert b.boardId == blueprint.boardId
            assert b.platform == blueprint.platform
            return

    assert False, "Blueprint not found"


async def test_get(project, blueprint):
    found_blueprint = await project.blueprints.get(blueprint.id)
    assert blueprint.name == found_blueprint.name


async def test_get_id(project, blueprint):
    blueprint_id = await project.blueprints.get_id(blueprint.name)
    assert blueprint.id == blueprint_id


async def test_delete(project, blueprint_to_delete):
    new_blueprint = blueprint_to_delete
    assert type(new_blueprint) == Blueprint

    await project.blueprints.delete(new_blueprint.id)

    with pytest.raises(Exception):
        await project.blueprints.delete(new_blueprint.id)


async def test_create(project, blueprintname_to_create):
    new_blueprint = await project.blueprints.create(blueprintname_to_create, boardId='nrf9160dk_nrf9160', platform='zephyr')
    assert new_blueprint.name == blueprintname_to_create
