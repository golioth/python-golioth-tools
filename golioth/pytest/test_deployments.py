import pytest
from pathlib import Path

pytestmark = pytest.mark.anyio

async def test_get_all(project, cohort_for_deployment, deployment):
    all_deployments = await cohort_for_deployment.deployments.get_all()
    for d in all_deployments:
        if d.id == deployment.id:
            assert d.name == deployment.name
            assert d.id == deployment.id
            assert d.artifact_ids == deployment.artifact_ids
            return

    assert False, "Deployment not found"


async def test_get(cohort_for_deployment, deployment):
    found_deployment = await cohort_for_deployment.deployments.get(deployment.id)
    assert found_deployment.id == deployment.id
    assert found_deployment.name == deployment.name
    assert found_deployment.artifact_ids == deployment.artifact_ids


async def test_get_id(cohort_for_deployment, deployment):
    found_id = await cohort_for_deployment.deployments.get_id(deployment.name)
    assert found_id == deployment.id


async def test_create(project, cohort_for_deployment, package_for_deployment, fake_binary,
                      rand_string):
    version = f'255.1.1-variant-{rand_string}'
    artifact = await project.artifacts.upload(Path(fake_binary), version, package_for_deployment.id)
    deployment_name = f'deployment-{rand_string}'
    new_deployment = await cohort_for_deployment.deployments.create(deployment_name, [artifact.id])

    all_deployments = await cohort_for_deployment.deployments.get_all()
    for d in all_deployments:
        if d.id == new_deployment.id:
            assert d.name == new_deployment.name
            assert d.id == new_deployment.id
            assert d.artifact_ids == new_deployment.artifact_ids
            return

    assert False, "Deployment not found"
