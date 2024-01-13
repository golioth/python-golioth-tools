#!/usr/bin/env python3

from base64 import b64decode
from datetime import datetime, timezone
import fnmatch
import json
from pathlib import Path
import re
import sys
from typing import Optional, Tuple, Union
import yaml

import asyncclick as click
from colorama import Fore, Style
from imgtool.image import Image, VerifyResult
from rich.console import Console

from golioth import Client, LogEntry, LogLevel, Project, RPCTimeout

create_set = set

console = Console()

class Config:
    def __init__(self):
        self.access_token: Optional[Path] = None
        self.api_key: Optional[str] = None
        self.default_project: Optional[str] = None
        self.api_url: Optional[str] = None

pass_config = click.make_pass_decorator(Config, ensure=True)

@click.group()
@click.option('-c', '--config-path', type=Path,
              help='Path to goliothctl configuration',
              default=Path.home() / '.golioth' / '.goliothctl.yaml')
@click.option('--api-key', help='Api key')
@pass_config
def cli(config, config_path, api_key):
    config.api_key = api_key

    with config_path.open('r') as fp:
        config_dict = yaml.load(fp, yaml.SafeLoader)
        if 'accesstoken' in config_dict:
            config.access_token = config_dict['accesstoken']
        if 'projectid' in config_dict:
            config.default_project = config_dict['projectid']
        if 'apiurl' in config_dict:
            config.api_url = config_dict['apiurl']

def rpc_params(params: str) -> Union[list, dict]:
    parsed = json.loads(params)

    return parsed

@cli.command()
@click.option('-d', '--device-name',
              help='Name of device on which RPC method will be called',
              required=True)
@click.argument('method')
@click.argument('params', required=False, type=rpc_params, nargs=-1)
@pass_config
async def call(config, device_name, method, params):
    """Call RPC method on device."""

    if len(params) == 1 and isinstance(params[0], list):
        params = params[0]

    try:
        with console.status(f'Waiting for reply from method {method}...'):
            client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
            project = await Project.get_by_id(client, config.default_project)
            # console.log(f'client: {client}')
            device = await project.device_by_name(device_name)
            # console.log(f'device: {device}')

            resp = await device.rpc.call(method, params)
    except RPCTimeout as e:
        console.print(f'Timeout on RPC method: {method}')
        return

    console.print(resp)


class MatchGlobRegexSwitch(click.ParamType):
    @staticmethod
    def regex(pattern: str):
        return pattern

    @staticmethod
    def glob(pattern: str):
        return fnmatch.translate(pattern)

    def convert(self, value, param, ctx):
        return getattr(self, value)


MATCH_GLOB_REGEX_SWITCH = MatchGlobRegexSwitch()


@cli.group()
def artifacts():
    """DFU artifacts related commands."""
    pass


@artifacts.command()
@click.option('-p', '--package', default='main', show_default=True,
              help='Package name')
@click.option('-r', 'release_rollout',
              help='Create release with the same release_tag (when specified once) and rollout (when specified twice).',
              count=True)
@click.option('-f', '--force',
              help='Force upload, by removing conflicting artifacts (and/or releases).',
              is_flag=True)
@click.option('-b', '--blueprint', default=None,
              help='Assign a Blueprint using the blueprintId.')
@click.argument('path', type=click.Path(exists=True))
@pass_config
async def upload(config, package, release_rollout, force, blueprint, path):
    """Upload new DFU artifact."""
    create_release = (release_rollout > 0)

    verify_result, version_bin, digest = Image.verify(path, None)
    if verify_result != VerifyResult.OK:
        raise RuntimeError('Invalid firmware file')

    version = '.'.join([str(x) for x in version_bin[:3]])

    with console.status('Uploading DFU artifact...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        if force:
            artifacts_to_remove = create_set()
            artifacts = await project.artifacts.get_all()

            artifacts_to_remove.update([a for a in artifacts
                                        if (a.version == version and
                                            a.package == package)])

            releases_to_remove = create_set()
            releases = await project.releases.get_all()

            if create_release:
                releases_to_remove.update([r for r in releases
                                           if version in r.release_tags])

            for artifact in artifacts_to_remove:
                releases_to_remove.update([r for r in releases
                                           if artifact.id in r.artifact_ids])

            for release in releases_to_remove:
                await project.releases.delete(release.id)

            for artifact in artifacts_to_remove:
                await project.artifacts.delete(artifact.id)

        artifact = await project.artifacts.upload(Path(path), version, package, blueprint)
        console.print(artifact)

        if create_release:
            release = await project.releases.create(artifact_ids=[artifact.id],
                                                    release_tags=[version],
                                                    rollout=(release_rollout > 1))

            console.print(release)


@artifacts.command()
@pass_config
async def list(config):
    """List DFU artifacts."""
    with console.status('Getting DFU artifacts...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        artifacts = await project.artifacts.get_all()
        for artifact in artifacts:
            console.print(artifact)


@artifacts.command()
@click.argument('artifact_id', nargs=-1, required=True)
@click.option('--by-package-version', '--pv', is_flag=True,
              help='Select artifact by "package@version" instead of artifact ID.')
@click.option('--hidden-glob', 'match_type', flag_value='glob',
              default=True,
              hidden=True,
              type=MATCH_GLOB_REGEX_SWITCH,
              help='Use glob match.')
@click.option('--regex', '-r', 'match_type', flag_value='regex',
              type=MATCH_GLOB_REGEX_SWITCH,
              help='Use regex match (instead of glob).')
@pass_config
async def delete(config, artifact_id, by_package_version, match_type):
    """Delete DFU artifact.

    \b
    Example invocations
    -------------------

    \b
    Delete artifact with package 'main' and version '1.0.0':
    $ golioth artifacts delete --pv main@1.0.0

    \b
    Delete all artifacts:
    $ golioth artifacts delete '*'

    \b
    Delete all version 2.x.x and 3.x.x artifacts from package 'main':
    $ golioth artifacts delete --pv 'main@[2-3].*.*'
    """
    if by_package_version:
        def artifact_match(pattern, artifact):
            return pattern.match(f'{artifact.package}@{artifact.version}') is not None
    else:
        def artifact_match(pattern, artifact):
            return pattern.match(artifact.id) is not None

    with console.status('Getting DFU artifacts...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        patterns = [re.compile(match_type(x)) for x in artifact_id]
        deleted = []

        for artifact in await project.artifacts.get_all():
            for pattern in patterns:
                if artifact_match(pattern, artifact):
                    await project.artifacts.delete(artifact.id)
                    console.print(f'Deleted: {artifact}')
                    deleted.append(artifact)
                    break

        if not deleted:
            console.print('No artifacts deleted!')


@cli.group()
def releases():
    """DFU releases related commands."""
    pass


@releases.command()
@click.option('artifact_ids', '--artifact', '-a', multiple=True, required=True,
              help='List of Artifacts included in this Release')
@click.option('release_tags', '--release-tag', '-t', multiple=True, default=[],
              help='List of unique release tags to assign to this Release')
@click.option('device_tags', '--device-tags', '-d', multiple=True, default=[],
              help='List of device Tag IDs to assign to this Release')
@click.option('--rollout', '-r', is_flag=True)
@pass_config
async def create(config, artifact_ids, release_tags, device_tags, rollout):
    """Create DFU release."""
    with console.status('Creating DFU release...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        await project.releases.create(artifact_ids, release_tags, device_tags, rollout)


@releases.command()
@click.argument('release_id', nargs=-1, required=True)
@click.option('--by-release-tag', '-t', is_flag=True,
              help='Select release by release tag instead of release ID.')
@click.option('--hidden-glob', 'match_type', flag_value='glob',
              default=True,
              hidden=True,
              type=MATCH_GLOB_REGEX_SWITCH,
              help='Use glob match.')
@click.option('--regex', '-r', 'match_type', flag_value='regex',
              type=MATCH_GLOB_REGEX_SWITCH,
              help='Use regex match (instead of glob).')
@pass_config
async def delete(config, release_id, by_release_tag, match_type):
    """Delete DFU releases.

    \b
    Example invocations
    -------------------

    \b
    Delete release with release_tag '1.0.0':
    $ golioth releases delete -t 1.0.0

    \b
    Delete all releases:
    $ golioth releases delete '*'

    \b
    Delete all releases with 2.x.x and 3.x.x release_tags:
    $ golioth releases delete -t '[2-3].*.*'
    """
    if by_release_tag:
        def artifact_match(pattern, release):
            for tag in release.release_tags:
                if pattern.match(tag):
                    return True

            return False
    else:
        def artifact_match(pattern, release):
            return pattern.match(release.id) is not None

    with console.status('Deleting DFU releases...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        patterns = [re.compile(match_type(r)) for r in release_id]
        deleted = []

        for release in await project.releases.get_all():
            for pattern in patterns:
                if artifact_match(pattern, release):
                    await project.releases.delete(release.id)
                    console.print(f'Deleted: {release}')
                    deleted.append(release)
                    break

        if not deleted:
            console.print('No releases deleted!')


@releases.command()
@pass_config
async def list(config):
    """List DFU releases."""
    with console.status('Getting DFU releases...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        releases = await project.releases.get_all()
        for release in releases:
            console.print(release)


@releases.command()
@click.argument('release_id', nargs=-1, required=True)
@click.option('--by-release-tag', '-t', is_flag=True,
              help='Select release by release tag instead of release ID.')
@click.option('--hidden-glob', 'match_type', flag_value='glob',
              default=True,
              hidden=True,
              type=MATCH_GLOB_REGEX_SWITCH,
              help='Use glob match.')
@click.option('--regex', '-r', 'match_type', flag_value='regex',
              type=MATCH_GLOB_REGEX_SWITCH,
              help='Use regex match (instead of glob).')
@pass_config
async def rollback(config, release_id, by_release_tag, match_type):
    """Rollout DFU releases.

    \b
    Example invocations
    -------------------

    \b
    Rollback release with tag '1.0.0':
    $ golioth releases rollback -t 1.0.0

    \b
    Rollback all releases:
    $ golioth releases rollback '*'

    \b
    Rollback all version 2.x.x and 3.x.x releases:
    $ golioth releases rollback -t '[2-3].*.*'
    """

    if by_release_tag:
        def artifact_match(pattern, release):
            for tag in release.release_tags:
                if pattern.match(tag):
                    return True

            return False
    else:
        def artifact_match(pattern, release):
            return pattern.match(release.id) is not None

    with console.status('Rollback DFU releases...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        patterns = [re.compile(match_type(r)) for r in release_id]
        deleted = []

        for release in await project.releases.get_all():
            for pattern in patterns:
                if artifact_match(pattern, release) and release.rollout == True:
                    await project.releases.rollout_set(release.id, False)
                    console.print(f'Rollback: {release}')
                    deleted.append(release)
                    break

        if not deleted:
            console.print('No release rollbacks!')


@cli.group()
def lightdb():
    """LightDB State related commands."""
    pass

@lightdb.command()
@click.option('-d', '--device-name',
              help='Name of device',
              required=True)
@click.argument('path')
@pass_config
async def get(config, device_name, path):
    """Get LightDB State value."""
    path = path.strip('/')

    with console.status('Getting LightDB State value...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)

        resp = await device.lightdb.get(path)

        console.print(resp)


@lightdb.command()
@click.option('-d', '--device-name',
              help='Name of device',
              required=True)
@click.argument('path')
@click.argument('value', type=json.loads)
@pass_config
async def set(config, device_name, path, value):
    """Set LightDB State value."""
    path = path.strip('/')

    with console.status('Setting LightDB State value...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)

        await device.lightdb.set(path, value)


@lightdb.command()
@click.option('-d', '--device-name',
              help='Name of device',
              required=True)
@click.argument('path')
@pass_config
async def delete(config, device_name, path):
    """Delete LightDB State value."""
    path = path.strip('/')

    with console.status('Deleting LightDB State value...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)

        await device.lightdb.delete(path)


@lightdb.command()
@click.option('-d', '--device-name',
              help='Name of device',
              required=True)
@click.argument('path')
@pass_config
async def monitor(config, device_name, path):
    """Monitor LightDB State path."""
    path = path.strip('/')

    with console.status('Monitoring LightDB State path...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)

        async for value in device.lightdb.iter(path):
            console.print(value)


@cli.group()
def stream():
    """LightDB Stream related commands."""
    pass


@stream.command()
@click.option('-d', '--device-name',
              help='Name of device',
              required=True)
@pass_config
async def monitor(config, device_name):
    """Monitor LightDB Stream."""
    with console.status('Monitoring LightDB Stream path...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)

        async for value in device.stream.iter():
            console.print(value)


@cli.group()
def certificate():
    """Certificates related commands."""
    pass


@certificate.command()
@pass_config
async def list(config):
    """Get certificates."""
    with console.status('Getting certificates...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        certs = await project.certificates.get_all()

        console.print([c.info for c in certs])


@certificate.command()
@click.argument('id')
@pass_config
async def info(config, id):
    """Get certificate by ID."""
    with console.status('Getting certificate...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        resp = await project.certificates.get(id)

        console.print(resp.info)


@certificate.command()
@click.option('-t', '--cert_type', type=click.Choice(['root', 'intermediate']), default='root')
@click.argument('cert_file', type=Path)
@pass_config
async def add(config, cert_type, cert_file):
    """Add certificate."""
    with console.status('Adding certificate...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        with cert_file.open('rb') as fp:
            resp = await project.certificates.add(cert_pem=fp.read(), cert_type=cert_type)

        console.print(resp)


@certificate.command()
@click.argument('id')
@pass_config
async def delete(config, id):
    """Delete certificate by ID."""
    with console.status(f'Deleting certificate {id}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        resp = await project.certificates.delete(cert_id=id)

        console.print(resp)


@cli.group()
def device():
    """Device related commands."""
    pass


@device.command()
@click.argument('name')
@pass_config
async def info(config, name):
    """Get info about device."""
    with console.status(f'Getting device {name} info...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        device = await project.device_by_name(name)

        console.print(device.info)


@device.command()
@pass_config
async def list(config):
    """List all devices."""
    with console.status('Getting devices...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        devices = await project.get_devices()

        console.print([d.info for d in devices])

@device.command()
@click.argument('name')
@click.argument('hardware_id')
@pass_config
async def create(config, name, hardware_id):
    """Create a device"""
    with console.status('Creating device...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        device = await project.create_device(name, hardware_id)

        console.print(device.info)

@device.command()
@click.argument('name')
@pass_config
async def delete(config, name):
    """Delete a device"""
    with console.status('Deleting device...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        await project.delete_device_by_name(name)

@device.command()
@click.argument('device_name')
@click.argument('blueprint_name')
@pass_config
async def add_blueprint(config, device_name, blueprint_name):
    """Add a Blueprint to Device using Device name and Blueprint name"""
    with console.status(f'Adding Blueprint: {blueprint_name} to {device_name}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)
        blueprint_id = await project.blueprints.get_id(blueprint_name)

        await device.add_blueprint(blueprint_id)

@device.command()
@click.argument('device_name')
@click.argument('blueprint_name')
@pass_config
async def remove_blueprint(config, device_name, blueprint_name):
    """Remove a Blueprint from Device using Device name and Blueprint name"""
    with console.status(f'Removing Blueprint: {blueprint_name} from {device_name}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)
        blueprint_id = await project.blueprints.get_id(blueprint_name)

        await device.remove_blueprint(blueprint_id)

@device.command()
@click.argument('name')
@click.argument('tag_id')
@pass_config
async def add_tag(config, name, tag_id):
    """Add a tag to device using tagId """
    with console.status(f'Add in tagId {tag_id}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(name)

        await device.add_tag(tag_id)

@device.command()
@click.argument('name')
@click.argument('tag_id')
@pass_config
async def remove_tag(config, name, tag_id):
    """Add a tag to device using tagId """
    with console.status(f'Add in tagId {tag_id}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(name)

        await device.remove_tag(tag_id)

@cli.group()
def credentials():
    """Device credential related commands."""
    pass

@credentials.command()
@click.option('-d', '--device-name', required = True)
@pass_config
async def list(config, device_name):
    """List all PSKs"""
    with console.status('Getting PSKs...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)

        psks = await device.credentials.list()

        console.print([psk.info for psk in psks])

@credentials.command()
@click.option('-d', '--device-name', required = True)
@click.argument('identity')
@click.argument('key')
@pass_config
async def add(config, device_name, identity, key):
    """Add PSK credential to device"""
    with console.status('Adding PSK to device...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)

        try:
            psk = await device.credentials.add(identity, key)
        except Exception as e:
            console.print(e)
            sys.exit(1)

        console.print(psk)

@credentials.command()
@click.option('-d', '--device-name', required = True)
@click.argument('credential-id')
@pass_config
async def delete(config, device_name, credential_id):
    """Delete device credential"""
    with console.status('Deleting device credential...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)
        device = await project.device_by_name(device_name)

        await device.credentials.delete(credential_id)

@cli.group()
def logs():
    """Logging service related commands."""
    pass


def level_map(level: LogLevel) -> Tuple[str, str, str]:
    if level == LogLevel.ERR:
        return 'err', Fore.RED + Style.BRIGHT, Style.RESET_ALL
    elif level == LogLevel.WRN:
        return 'wrn', Fore.YELLOW + Style.BRIGHT, Style.RESET_ALL
    elif level == LogLevel.DBG:
        return 'dbg', Style.DIM, Style.RESET_ALL

    return level.name.lower(), '', ''


def format_hexdump(indent_size: int, data: bytes):
    indent = ' ' * indent_size

    return indent + ' '.join([f'{x:02x}' for x in data])


def log_format_default(log: LogEntry) -> str:
    return f'[{log.datetime}] <{log.level.name}> {log.module} {log.message}'


def print_log_default(log: LogEntry):
    console.print(log_format_default(log))


def log_format_zephyr(log: LogEntry) -> str:
    if 'uptime' not in log.metadata:
        return f'GENERIC {log_format_default(log)}'

    ts = datetime.fromtimestamp(log.metadata['uptime'] / 1000000, tz=timezone.utc)
    ts_str = ts.strftime('%H:%M:%S') + f'.{ts.microsecond // 1000:03},{ts.microsecond % 1000:03}'

    level, pre, post = level_map(log.level)

    pre_msg = f'[{ts_str}] {pre}<{level}> {log.module}: '

    if 'func' in log.metadata:
        pre_msg += f'{log.metadata["func"]}: '

    formatted = f'{pre_msg}{log.message}'

    if 'hexdump' in log.metadata:
        formatted += '\n'
        formatted += format_hexdump(len(pre_msg) - len(pre),
                                    b64decode(log.metadata['hexdump']))

    if post:
        formatted += post

    return formatted


def print_log_zephyr(log: LogEntry):
    print(log_format_zephyr(log))


@logs.command()
@click.option('-d', '--device-name',
              help='Name of device from which logs should be printed')
@click.option('-f', '--follow',
              help='Continuously print new entries as they are appended to the logging service',
              is_flag=True)
@click.option('-n', '--lines',
              help='Limit the number of log entries shows',
              type=int, default=20)
@click.option('--format',
              help='Format',
              type=click.Choice(['default', 'zephyr']))
@pass_config
async def tail(config, device_name, follow, lines, format):
    """Show the most recent log entries."""
    client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
    project = await Project.get_by_id(client, config.default_project)

    if device_name:
        device = await project.device_by_name(device_name)
        logs_provider = device
    else:
        logs_provider = project

    if format == 'zephyr':
        print_log = print_log_zephyr
    else:
        print_log = print_log_default

    if follow:
        async for log in logs_provider.logs_iter(lines=lines):
            print_log(log)

    logs = await logs_provider.get_logs()
    for log in logs[-lines:]:
        print_log(log)


@cli.group()
def settings():
    """Settings service related commands."""
    pass


@settings.command()
@click.option('-d', '--device-name',
              help='Name of device')
@click.argument('key')
@pass_config
async def get(config, device_name, key):
    """Get setting value of KEY."""
    try:
        with console.status(f'Getting setting value of {key}...'):
            client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
            project = await Project.get_by_id(client, config.default_project)

            if device_name is not None:
                device = await project.device_by_name(device_name)
                resp = await device.settings.get(key)
            else:
                resp = await project.settings.get(key)
    except KeyError:
        console.print(f'No such setting with key {key}')
        return

    console.print(resp)


@settings.command()
@click.option('-d', '--device-name',
              help='Name of device')
@pass_config
async def get_all(config, device_name):
    """Get all settings values."""
    with console.status('Getting settings...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        if device_name is not None:
            device = await project.device_by_name(device_name)
            resp = await device.settings.get_all()
        else:
            resp = await project.settings.get_all()

        console.print(resp)


@settings.command()
@click.option('-d', '--device-name',
              help='Name of device')
@click.argument('key')
@click.argument('value', type=json.loads)
@pass_config
async def set(config, device_name, key, value):
    """Set setting value of KEY to VALUE."""
    try:
        with console.status(f'Setting {key} to {value}...'):
            client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
            project = await Project.get_by_id(client, config.default_project)

            if device_name is not None:
                device = await project.device_by_name(device_name)
                resp = await device.settings.set(key, value)
            else:
                resp = await project.settings.set(key, value)

    except KeyError:
        console.print(f'No such setting with key {key}')
        return

    console.print(resp)


@settings.command()
@click.option('-d', '--device-name',
              help='Name of device')
@click.argument('key')
@pass_config
async def delete(config, device_name, key):
    """Delete KEY from settings."""
    try:
        with console.status(f'Deleting {key} from settings...'):
            client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
            project = await Project.get_by_id(client, config.default_project)

            if device_name is not None:
                device = await project.device_by_name(device_name)
                await device.settings.delete(key)
            else:
                await project.settings.delete(key)

    except KeyError:
        console.print(f'No such setting with key {key}')
        return


@cli.group()
def blueprints():
    """Blueprint related commands."""
    pass

@blueprints.command()
@pass_config
async def list(config):
    """List all Blueprints"""
    with console.status('Getting Blueprints...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        blueprints = await project.blueprints.get_all()

        console.print([blueprint for blueprint in blueprints])

@blueprints.command()
@click.argument('blueprint_id')
@pass_config
async def get(config, blueprint_id):
    """List single Blueprint by blueprintId"""
    with console.status(f'Getting Blueprint {blueprint_id}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        blueprint = await project.blueprints.get(blueprint_id)

        console.print(blueprint)

@blueprints.command()
@click.argument('blueprint_name')
@pass_config
async def get_id(config, blueprint_name):
    """Get Blueprint ID by name"""
    with console.status(f'Getting Blueprint {blueprint_name}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        b_id = await project.blueprints.get_id(blueprint_name)

        console.print(b_id)

@blueprints.command()
@click.argument('blueprint_name')
@click.option('-p', '--platform', default=None,
              help='Platform: Zephyr or blank. When Zephyr is selected a boardId must be provided.')
@click.option('-b', '--board', default=None,
              help='boardId as defined by Zephyr RTOS.')
@pass_config
async def create(config, blueprint_name, platform, board):
    """Create new Blueprint using name"""
    with console.status(f'Adding Blueprint: {blueprint_name}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        try:
            await project.blueprints.create(blueprint_name, platform=platform, boardId=board)
        except Exception as e:
            console.print(e)
            sys.exit(1)

@blueprints.command()
@click.argument('blueprint_id')
@pass_config
async def delete(config, blueprint_id):
    """Delete Blueprint using blueprintId"""
    with console.status(f'Deleting Blueprint: {blueprint_id}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        try:
            await project.blueprints.delete(blueprint_id)
        except Exception as e:
            console.print(e)
            sys.exit(1)


@cli.group()
def tags():
    """Tag related commands."""
    pass

@tags.command()
@pass_config
async def list(config):
    """List all Tags"""
    with console.status('Getting Tags...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        tags = await project.tags.get_all()

        console.print([tag for tag in tags])

@tags.command()
@click.argument('tag_id')
@pass_config
async def get(config, tag_id):
    """List single Tag by tagId"""
    with console.status(f'Getting Tag {tag_id}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        tag = await project.tags.get(tag_id)

        console.print(tag)

@tags.command()
@click.argument('tag_name')
@pass_config
async def get_id(config, tag_name):
    """Get Tag ID by name"""
    with console.status(f'Getting Tag ID for {tag_name}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        b_id = await project.tags.get_id(tag_name)

        console.print(b_id)

@tags.command()
@click.argument('tag_name')
@pass_config
async def create(config, tag_name):
    """Create new Tag using name"""
    with console.status(f'Adding Tag: {tag_name}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        try:
            await project.tags.create(tag_name)
        except Exception as e:
            console.print(e)
            sys.exit(1)

@tags.command()
@click.argument('tag_id')
@pass_config
async def delete(config, tag_id):
    """Delete Tag using tagId"""
    with console.status(f'Deleting Tag: {tag_id}...'):
        client = Client(api_url = config.api_url, api_key = config.api_key, access_token = config.access_token)
        project = await Project.get_by_id(client, config.default_project)

        try:
            await project.tags.delete(tag_id)
        except Exception as e:
            console.print(e)
            sys.exit(1)


def main():
    cli(_anyio_backend='trio')


if __name__ == '__main__':
    main()
