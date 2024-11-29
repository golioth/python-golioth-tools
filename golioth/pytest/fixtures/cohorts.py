import golioth
import pytest
from fixtures.rand_name import NAME_PREFIX, get_random_name

@pytest.fixture(scope="module")
async def cohort(project):
    cohort_name = get_random_name('cohort')
    cohort = await project.cohorts.create(cohort_name)
    yield cohort

    await project.cohorts.delete(cohort.id)


@pytest.fixture(scope="module")
async def cohort_to_delete(project):
    cohort_name = get_random_name('cohort')
    cohort = await project.cohorts.create(cohort_name)
    yield cohort

    try:
        await project.cohorts.delete(cohort.id)
    except:
        pass


@pytest.fixture(scope="module")
async def cohort_to_rename(project):
    cohort_name = get_random_name('cohort')
    cohort = await project.cohorts.create(cohort_name)
    yield cohort

    try:
        await project.cohorts.delete(cohort.id)
    except:
        pass

@pytest.fixture(scope="module")
async def cohortname_to_create(project):
    cohort_name = get_random_name('cohort')
    yield cohort_name

    cohort_id = await project.cohorts.get_id(cohort_name)
    if cohort_id is not None:
        await project.cohorts.delete(cohort_id)

@pytest.fixture(scope="function")
def cohort_randname():
    return get_random_name('cohort')
