"""Value-free reporting for explicitly supplied local Compose files."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from .analyzer import MAX_BYTES, SafeError, analyze, load_compose


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'error: invalid command arguments; use --help.\n')


def main(argv=None):
    parser = Parser(description='Read-only offline Docker Compose exposure checks.')
    parser.add_argument('compose')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    parser.add_argument('--fail-on', choices=('high', 'medium', 'low', 'never'), default='never')
    args = parser.parse_args(argv)
    try:
        path = Path(args.compose)
        if not path.is_file():
            raise SafeError('Input must be a readable regular file.')
        with path.open('rb') as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise SafeError('Compose input exceeds the supported size limit.')
        findings = analyze(load_compose(raw.decode('utf-8-sig')))
    except (SafeError, OSError, UnicodeError, RecursionError):
        print('error: unable to inspect supported Compose input safely; check file, size, and schema.', file=sys.stderr)
        return 2
    summary = dict(sorted(Counter(item['severity'] for item in findings).items()))
    if args.format == 'json':
        print(json.dumps({'findings': findings, 'summary': summary}, indent=2, sort_keys=True))
    else:
        for item in findings:
            print(f"{item['severity'].upper()} {item['rule']} service={item['service']} field={item['field']}: {item['message']}")
        print(f'Findings: {len(findings)}. Offline declarations only; runtime exposure is unverified.')
    rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'never': 4}
    return int(any(rank[item['severity']] >= rank[args.fail_on] for item in findings))


if __name__ == '__main__':
    raise SystemExit(main())
