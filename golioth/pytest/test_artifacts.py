import pytest
from golioth import Artifact
from pathlib import Path

pytestmark = pytest.mark.anyio

async def test_get_all(project, artifact):
    all_artifacts = await project.artifacts.get_all()
    for a in all_artifacts:
        if a.id == artifact.id:
            assert a.package == artifact.package
            assert a.version == artifact.version
            assert a.blueprint == artifact.blueprint
            return

    assert False, "Artifact not found"


async def test_get(project, artifact):
    found_artifact = await project.artifacts.get(artifact.id)

    assert found_artifact.package == artifact.package
    assert found_artifact.version == artifact.version
    assert found_artifact.blueprint == artifact.blueprint


async def test_delete(project, artifact_to_delete):
    new_artifact = artifact_to_delete
    assert type(new_artifact) == Artifact

    await project.artifacts.delete(new_artifact.id)

    with pytest.raises(Exception):
        await project.artifacts.delete(new_artifact.id)


async def test_create(project, new_artifact_info):
    new_artifact = await project.artifacts.upload(path = Path(new_artifact_info['binary']),
                                                  version = new_artifact_info['version'],
                                                  package = new_artifact_info['package'],
                                                  blueprint_id = new_artifact_info['blueprint_id'])
    assert new_artifact.package == new_artifact_info['package']
    assert new_artifact.version == new_artifact_info['version']
    assert new_artifact.blueprint == new_artifact_info['blueprint_id']
