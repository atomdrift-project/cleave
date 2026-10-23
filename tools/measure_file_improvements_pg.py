"""Compare native JSONB/TOAST for the file codec experiments.

Usage: python3 tools/measure_file_improvements_pg.py SOCKET PORT CASE_DIRECTORY SCHEMA
Only connects to an explicitly named disposable Unix socket. Split comparisons
include all occurrences, light analysis summaries and full payload keys, and
deduplicate only exactly equal canonical analyses. No production schema/WAL.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from measure_context_retention_pg import field

VARIANTS = ('v8', 'context_only', 'trimmed', 'shared')
PLACEMENT = {'id', 'path', 'dp', 'depth', 'pid', 'rel', 'via', 'role'}


def wire(v):
    return json.dumps(v, ensure_ascii=False, separators=(',', ':'), sort_keys=True)


def split_flat(doc):
    if len(doc['files']) == 1:
        return [doc]
    metadata = {k: doc[k] for k in ('rev', 'fp') if doc.get(k) is not None}
    manifest = dict(v='split-2' if doc['v'] == 'file-2' else 'split-1', **metadata, files=[], a=[])
    if doc.get('fetched'):
        manifest['fetched'] = doc['fetched']
    leaves, lookup = [], {}
    for file in doc['files']:
        payload = {k: v for k, v in file.items() if k not in PLACEMENT}
        payload.update(id=0, path='')
        leaf = dict(v=doc['v'], **metadata, files=[payload])
        canonical = wire(leaf)
        if canonical not in lookup:
            lookup[canonical] = len(leaves)
            leaves.append(leaf)
            summary = {k: payload[k] for k in ('sha', 'type', 'size', 'mol', 'analysis_gaps') if k in payload}
            summary['risk'] = payload.get('risk', 0)
            summary['key'] = hashlib.sha256(canonical.encode()).hexdigest()
            manifest['a'].append(summary)
        placement = {k: v for k, v in file.items() if k in PLACEMENT}
        placement['a'] = lookup[canonical]
        manifest['files'].append(placement)
    return [manifest, *leaves]


def main():
    socket, port, directory, schema = sys.argv[1:]
    root = pathlib.Path(directory)
    assert pathlib.Path(socket).is_dir() and port.isdigit()
    assert re.fullmatch(r'[a-z][a-z0-9_]*', schema)
    proc = subprocess.Popen(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-h', socket, '-p', port, '-d', 'postgres'], stdin=subprocess.PIPE, text=True)
    out = proc.stdin
    out.write(f'CREATE SCHEMA {schema};\n')
    out.write(f'CREATE UNLOGGED TABLE {schema}.staged(sample text, variant text, layout text, doc jsonb);\n')
    out.write(f'COPY {schema}.staged FROM STDIN;\n')
    for case in sorted(p for p in root.iterdir() if p.is_dir() and (p/'v8.json').exists()):
        for variant in VARIANTS:
            doc = json.loads((case/(variant+'.json')).read_bytes())
            def emit(layout, value):
                out.write('\t'.join(map(field, (case.name, variant, layout, wire(value))))+'\n')
            emit('joined', doc)
            rows = [json.loads(line) for line in (case/'shared.split.jsonl').read_text().splitlines()] if variant == 'shared' else split_flat(doc)
            for row in rows:
                emit('split', row)
    out.write('\\.\n')
    queries = []
    for codec in ('pglz', 'lz4'):
        for variant in VARIANTS:
            for layout in ('joined', 'split'):
                table = f'{schema}.{variant}_{layout}_{codec}'
                out.write(f'CREATE UNLOGGED TABLE {table}(sample text, doc jsonb COMPRESSION {codec});\n')
                out.write(f"INSERT INTO {table} SELECT sample, doc::text::jsonb FROM {schema}.staged WHERE variant='{variant}' AND layout='{layout}';\n")
                queries.append(f"SELECT '{codec}' codec,'{variant}' variant,'{layout}' layout,sample,count(*) records,sum(pg_column_size(doc)) payload_bytes FROM {table} GROUP BY sample")
    out.write('\\pset format csv\n')
    out.write('\\o '+str(root/'pg-payload.csv')+'\n')
    out.write(' UNION ALL '.join(queries)+' ORDER BY codec,sample,layout,variant;\n')
    out.write('\\o '+str(root/'pg-relations.csv')+'\n')
    out.write(f"SELECT relname,pg_total_relation_size(oid) total_bytes FROM pg_class WHERE relnamespace='{schema}'::regnamespace AND relkind='r' ORDER BY relname;\n")
    out.write('\\o\n')
    out.close()
    if proc.wait():
        raise SystemExit(proc.returncode)


if __name__ == '__main__':
    main()
