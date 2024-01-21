import pytest
from golioth import Release

pytestmark = pytest.mark.anyio

async def test_get_all(project, release):
    all_releases = await project.releases.get_all()
    for r in all_releases:
        if r.id == release.id:
            assert r.release_tags == release.release_tags
            assert r.device_tags == release.device_tags
            assert r.artifact_ids == release.artifact_ids
            assert r.rollout == release.rollout

            return

    assert False, "Release not found"


async def test_get(project, release):
    found_release = await project.releases.get(release.id)

    assert found_release.release_tags == release.release_tags
    assert found_release.device_tags == release.device_tags
    assert found_release.artifact_ids == release.artifact_ids
    assert found_release.rollout == release.rollout


async def test_delete(project, release_to_delete):
    new_release = release_to_delete
    assert type(new_release) == Release

    await project.releases.delete(new_release.id)

    with pytest.raises(Exception):
        await project.releases.delete(new_release.id)


async def test_create(project, new_release_info):
    new_release = await project.releases.create(artifact_ids = [new_release_info['artifact_id']],
                                                release_tags = [new_release_info['release_tag']],
                                                device_tags = [new_release_info['tag_id']],
                                                rollout = True)

    assert new_release.artifact_ids == [new_release_info['artifact_id']]
    assert new_release.release_tags == [new_release_info['release_tag']]
    assert new_release.device_tags == [new_release_info['tag_id']]
    assert new_release.rollout == True


async def test_rollout_set(project, release):
    found_release = await project.releases.get(release.id)

    assert found_release.release_tags == release.release_tags
    assert found_release.device_tags == release.device_tags
    assert found_release.artifact_ids == release.artifact_ids
    assert found_release.rollout == release.rollout

    await project.releases.rollout_set(release.id, not release.rollout)

    found_release = await project.releases.get(release.id)

    assert found_release.release_tags == release.release_tags
    assert found_release.device_tags == release.device_tags
    assert found_release.artifact_ids == release.artifact_ids
    assert found_release.rollout == (not release.rollout)
