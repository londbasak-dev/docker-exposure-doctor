"""Inspect declarations only; no Docker client, environment expansion, or network."""
import ipaddress
import posixpath
import re
import yaml

MAX_BYTES = 2 * 1024 * 1024
SECRET_NAME = re.compile(r'(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)', re.I)


class SafeError(Exception):
    """Fixed non-sensitive diagnostic, never a YAML parser excerpt."""


class StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise SafeError('YAML mappings require unique string keys.')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_compose(text, max_bytes=MAX_BYTES):
    if not 1 <= max_bytes <= MAX_BYTES or len(text.encode('utf-8')) > max_bytes:
        raise SafeError('Compose input exceeds the supported size limit.')
    try:
        depth, tokens = 0, 0
        for token in yaml.scan(text):
            tokens += 1
            # Deliberately reject aliases, including merge keys, rather than expand them.
            if isinstance(token, yaml.tokens.AliasToken):
                raise SafeError('YAML aliases are unsupported; provide a flattened file.')
            if isinstance(token, (yaml.tokens.BlockMappingStartToken, yaml.tokens.BlockSequenceStartToken,
                                  yaml.tokens.FlowMappingStartToken, yaml.tokens.FlowSequenceStartToken)):
                depth += 1
            if isinstance(token, (yaml.tokens.BlockEndToken, yaml.tokens.FlowMappingEndToken, yaml.tokens.FlowSequenceEndToken)):
                depth -= 1
            if depth > 64 or tokens > 100000:
                raise SafeError('Compose structure exceeds supported complexity limits.')
        return yaml.load(text, Loader=StrictLoader)
    except SafeError:
        raise
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise SafeError('Unable to parse supported Compose YAML safely.') from None


def _loopback(host):
    try:
        address = ipaddress.ip_address(str(host).strip('[]'))
        mapped = getattr(address, 'ipv4_mapped', None)
        return mapped.is_loopback if mapped is not None else address.is_loopback
    except ValueError:
        return False


def _source(volume):
    if isinstance(volume, dict):
        return str(volume.get('source', '')) if volume.get('type') == 'bind' else ''
    if isinstance(volume, str):
        match = re.match(r'^([A-Za-z]:[\\/][^:]*):', volume)
        if match:
            return match[1]
        source = volume.split(':', 1)[0] if ':' in volume else ''
        # Bare names refer to Docker-managed volumes, not host paths.
        return source if source.startswith(('/', '.', '~', '\\')) else ''
    raise SafeError('Unsupported volume declaration.')


def _validate_service(service):
    if not isinstance(service, dict):
        raise SafeError('Each service must be a mapping.')
    for field in ('ports', 'volumes', 'cap_add'):
        if field in service and not isinstance(service[field], list):
            raise SafeError('Unsupported service list field.')
    if 'environment' in service and not isinstance(service['environment'], (dict, list)):
        raise SafeError('Unsupported environment declaration.')
    if 'privileged' in service and not isinstance(service['privileged'], bool):
        raise SafeError('Privileged must be a YAML boolean.')


def analyze(document):
    if not isinstance(document, dict) or not isinstance(document.get('services'), dict):
        raise SafeError('Compose must contain a services mapping.')
    findings = []
    for index, (name, service) in enumerate(document['services'].items(), 1):
        _validate_service(service)
        # Only conventional bounded names are echoed; arbitrary names receive an ordinal.
        label = name if isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name) else f'service-{index}'

        def add(rule, severity, field, message):
            findings.append({'rule': rule, 'severity': severity, 'service': label, 'field': field, 'message': message})

        if service.get('privileged') is True:
            add('privileged', 'high', 'privileged', 'Remove privileged mode and grant only required permissions.')
        if service.get('network_mode') == 'host':
            add('host-network', 'high', 'network_mode', 'Host networking removes normal network namespace separation.')
        if service.get('pid') == 'host':
            add('host-pid', 'high', 'pid', 'Host PID mode exposes the host process namespace.')
        if any(str(cap).upper() in ('ALL', 'SYS_ADMIN') for cap in service.get('cap_add', [])):
            add('powerful-capability', 'high', 'cap_add', 'Broad capabilities increase host impact; minimize capabilities.')
        for volume in service.get('volumes', []):
            raw_source = _source(volume).replace('\\', '/').lower()
            if raw_source.startswith('/'):
                raw_source = posixpath.normpath(raw_source)
            source = raw_source.rstrip('/') if raw_source != '/' else '/'
            if 'docker.sock' in source or 'docker_engine' in source:
                add('docker-socket', 'high', 'volumes', 'Docker control socket access can grant host-level control, including read-only binds.')
            elif source in ('/', '/etc', '/proc', '/sys', '/dev', '/root', '/home', '/var', '/usr', '/run') or re.fullmatch(r'[a-z]:', source):
                add('broad-host-mount', 'high', 'volumes', 'A broad host filesystem bind increases host exposure.')
        for port in service.get('ports', []):
            host = ''
            if isinstance(port, dict):
                if 'published' not in port:
                    continue
                host = port.get('host_ip', '')
            elif isinstance(port, (str, int)) and not isinstance(port, bool):
                parts = str(port).rsplit(':', 2)
                if str(port).startswith('['):
                    match = re.match(r'^\[([^]]+)\]:', str(port))
                    host = match[1] if match else ''
                elif len(parts) == 3:
                    host = parts[0]
                # Bare target ports in `ports` request a random host publication.
            else:
                raise SafeError('Unsupported port declaration.')
            if _loopback(host):
                add('loopback-port', 'info', 'ports', 'Published port is declared loopback-only; verify actual runtime binding.')
            else:
                add('published-port', 'medium', 'ports', 'Published port is not explicitly loopback-only; restrict binding and firewall access.')
        user = service.get('user')
        if user is None or user == '':
            add('image-user-unknown', 'low', 'user', 'User is unspecified; inspect the image default and select a non-root identity.')
        elif str(user).split(':', 1)[0] == 'root' or re.fullmatch(r'\+?0+', str(user).split(':', 1)[0]):
            add('root-user', 'medium', 'user', 'Service explicitly requests root; select a non-root identity where possible.')
        environment = service.get('environment', {})
        if isinstance(environment, dict):
            pairs = environment.items()
        else:
            if any(not isinstance(entry, str) for entry in environment):
                raise SafeError('Environment list entries must be strings.')
            pairs = (entry.split('=', 1) if '=' in entry else (entry, None) for entry in environment)
        for key, value in pairs:
            if SECRET_NAME.search(str(key)) and value is not None and str(value) != '':
                # Pure environment references are not literal secret assignments. Defaults are.
                if isinstance(value, str) and re.fullmatch(r'\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*', value):
                    continue
                add('inline-secret', 'high', 'environment', 'Potential secret is assigned inline; use an appropriate secret provider.')
    return findings
