import pytest
from golioth import Cohort

pytestmark = pytest.mark.anyio

async def test_get_all(project, cohort):
    all_cohorts = await project.cohorts.get_all()
    for c in all_cohorts:
        if c.id == cohort.id:
            assert c.name == cohort.name
            assert c.id == cohort.id
            assert c.device_count == cohort.device_count
            assert c.active_deployment_id == cohort.active_deployment_id
            return

    assert False, "Cohort not found"


async def test_get(project, cohort):
    found_cohort = await project.cohorts.get(cohort.id)
    assert found_cohort.name == cohort.name
    assert found_cohort.device_count == cohort.device_count
    assert found_cohort.active_deployment_id == cohort.active_deployment_id


async def test_get_id(project, cohort):
    found_id = await project.cohorts.get_id(cohort.name)
    assert found_id == cohort.id

async def test_create(project, cohortname_to_create):
    new_cohort = await project.cohorts.create(cohortname_to_create)
    assert new_cohort.name == cohortname_to_create

async def test_delete(project, cohort_to_delete):
    new_cohort = cohort_to_delete
    assert type(new_cohort) == Cohort

    await project.cohorts.delete(new_cohort.id)

    with pytest.raises(Exception):
        await project.cohorts.delete(new_cohort.id)

async def test_update(project, cohort_to_rename, cohort_randname):
    renamed_cohort = await project.cohorts.update(cohort_to_rename.id, cohort_randname)
    assert renamed_cohort.name == cohort_randname

    fetched_cohort = await project.cohorts.get(cohort_to_rename.id)
    assert fetched_cohort.name == cohort_randname
