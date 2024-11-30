import pytest
from golioth import Package

pytestmark = pytest.mark.anyio

async def test_get_all(project, package):
    all_packages = await project.packages.get_all()

    for p in all_packages:
        if p.id == package.id:
            assert p.id == package.id
            assert p.description == package.description
            assert p.metadata == package.metadata
            return

    assert False, "Package not found"


async def test_get(project, package):
    found_package = await project.packages.get(package.id)
    assert found_package.id == package.id
    assert found_package.description == package.description
    assert found_package.metadata == package.metadata


async def test_create(project, package_id_to_create, randnames):
    new_package = await project.packages.create(package_id_to_create,
                                                randnames.description,
                                                randnames.metadata)
    assert new_package.id == package_id_to_create
    assert new_package.description == randnames.description
    assert new_package.metadata == randnames.metadata


async def test_delete(project, package_to_delete):
    new_package = package_to_delete
    assert type(new_package) == Package

    await project.packages.delete(new_package.id)

    with pytest.raises(Exception):
        await project.packages.delete(new_package.id)


async def test_update(project, package_to_update, randnames):
    assert package_to_update.description != randnames.description
    assert package_to_update.metadata != randnames.metadata

    await project.packages.update(package_to_update.id, randnames.description, randnames.metadata)

    refetch_package = await project.packages.get(package_to_update.id)
    assert refetch_package.id == package_to_update.id
    assert refetch_package.description == randnames.description
    assert refetch_package.metadata == randnames.metadata

    await project.packages.update(package_to_update.id, "", {})

    refetch_package = await project.packages.get(package_to_update.id)
    assert refetch_package.id == package_to_update.id
    assert refetch_package.description == ""
    assert refetch_package.metadata == {}
