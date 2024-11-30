import pytest
from pathlib import Path
from fixtures.rand_name import get_random_name

def generate_fake_bin():
    fake_binary = f'{get_random_name("artifact")}.bin'

    with open(fake_binary, 'wb') as f:
        f.write(bytes(fake_binary, 'utf8'))
    return fake_binary

@pytest.fixture(scope="module")
async def cohort_for_deployment(project):
    cohort = await project.cohorts.create(get_random_name('cohort'))

    yield cohort
    # This will be torn down by the deployment fixture


@pytest.fixture(scope="module")
async def package_for_deployment(project):
    package = await project.packages.create(f'{get_random_name("main")}', "", {})

    yield package
    # This will be torn down by the deployment fixture


@pytest.fixture(scope="module")
async def deployment(project, cohort_for_deployment, package_for_deployment):
    version = f'255.13.37-{get_random_name("variant")}'
    fake_binary = generate_fake_bin()
    artifact = await project.artifacts.upload(Path(fake_binary), version, package_for_deployment.id)
    Path.unlink(Path(fake_binary))

    deployment_name = get_random_name('deployment')
    deployment = await cohort_for_deployment.deployments.create(deployment_name, [artifact.id])
    yield deployment

    await project.cohorts.delete(cohort_for_deployment.id)
    await project.packages.delete(package_for_deployment.id)


@pytest.fixture(scope="module")
async def fake_binary():
    fake_binary = generate_fake_bin()
    yield fake_binary

    Path.unlink(Path(fake_binary))

@pytest.fixture(scope="function")
async def rand_string():
    yield get_random_name().split('-')[1]
