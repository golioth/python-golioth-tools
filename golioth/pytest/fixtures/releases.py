import golioth
import pytest
from fixtures.rand_name import get_random_name

@pytest.fixture(scope="module")
async def release(project, artifact, tag):
    release_tag = f'release-{get_random_name()}'
    release = await project.releases.create([artifact.id], [release_tag], [tag.id], False)
    yield release

    await project.releases.delete(release.id)


@pytest.fixture(scope="module")
async def release_to_delete(project, artifact, tag):
    release_tag = f'release-{get_random_name()}'
    release = await project.releases.create([artifact.id], [release_tag], [tag.id], False)
    yield release

    try:
        await project.release.delete(release.id)
    except:
        pass


@pytest.fixture(scope="module")
async def new_release_info(project, artifact, tag):
    release_tag = f'release-{get_random_name()}'
    release_info = {'artifact_id': artifact.id,
                'release_tag': release_tag,
                'tag_id': tag.id}

    yield release_info

    try:
        releases = await project.releases.get_all()
        for r in releases:
            if (r.artifact_ids == [release_info['artifact_id']] and
                r.release_tags == [release_info['release_tag']] and
                r.device_tags == [release_info['tag_id']]):

                await project.releases.delete(r.id)
                break

    except:
        pass
