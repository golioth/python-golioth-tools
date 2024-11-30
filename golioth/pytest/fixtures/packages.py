import golioth
import pytest
from fixtures.rand_name import NAME_PREFIX, get_random_name

class RandPackageProps():
    def __init__(self):
        self.id = get_random_name('package')
        self.description = get_random_name('description')
        self.metadata = { "prop1" : get_random_name('value'),
                          "prop2" : get_random_name('value')
                         }


@pytest.fixture(scope="module")
async def package(project):
    rand_package_values = RandPackageProps()

    package_id = rand_package_values.id
    package_description = rand_package_values.description
    package_meta = rand_package_values.metadata

    package = await project.packages.create(package_id, package_description, package_meta)
    yield package

    await project.packages.delete(package.id)


@pytest.fixture(scope="module")
async def package_id_to_create(project):
    package_id = get_random_name('package')
    yield package_id

    try:
        await project.packages.delete(package_id)
    except:
        pass


@pytest.fixture(scope="module")
async def package_to_delete(project):
    rand_package_values = RandPackageProps()
    package = await project.packages.create(rand_package_values.id,
                                            rand_package_values.description,
                                            rand_package_values.metadata)
    yield package

    try:
        await project.packages.delete(package.id)
    except:
        pass


@pytest.fixture(scope="module")
async def package_to_update(project):
    package_id = get_random_name('package')
    package = await project.packages.create(package_id)
    yield package

    try:
        await project.packages.delete(package.id)
    except:
        pass


@pytest.fixture(scope="function")
def randnames() -> RandPackageProps:
    return RandPackageProps()
