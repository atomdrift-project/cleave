"""Native JSONB/TOAST benchmark, only for a disposable PostgreSQL database.

Usage: python3 tools/measure_context_retention_pg.py SOCKET PORT BENCH_DIRECTORY [SCHEMA]
BENCH_DIRECTORY contains numbered directories with v8/full/trimmed.json from
the native measure_context_retention example. Creates schema ctxbench, failing
if it already exists. Never connects using ambient PGHOST or a production URL.
"""
import json
import pathlib
import re
import subprocess
import sys


def field(s):
    return s.replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n').replace('\r', '\\r')


def main():
    socket, port, directory = sys.argv[1:4]
    schema = sys.argv[4] if len(sys.argv) > 4 else 'ctxbench'
    assert re.fullmatch(r'[a-z][a-z0-9_]*', schema)
    root = pathlib.Path(directory)
    assert pathlib.Path(socket).is_dir() and port.isdigit()
    proc = subprocess.Popen(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-h', socket,
                             '-p', port, '-d', 'postgres'], stdin=subprocess.PIPE,
                            text=True)
    out = proc.stdin
    out.write(f'CREATE SCHEMA {schema};\n')
    out.write(f'CREATE UNLOGGED TABLE {schema}.staged(sample text, variant text, layout text, doc jsonb);\n')
    out.write(f'COPY {schema}.staged FROM STDIN;\n')
    for sample in sorted(p for p in root.iterdir() if p.is_dir() and (p/'v8.json').exists()):
        for variant in ('v8', 'full', 'trimmed'):
            doc = json.loads((sample/(variant+'.json')).read_text())
            emit = lambda layout, value: out.write('\t'.join(map(field, (
                sample.name, variant, layout, json.dumps(value, ensure_ascii=False, separators=(',', ':')))))+'\n')
            emit('joined', doc)
            stub_keys = {'id', 'sha', 'path', 'type', 'depth', 'size', 'risk', 'mol', 'pid'}
            stubs = [{k: v for k, v in f.items() if k in stub_keys}
                     for f in doc['files'] if f.get('depth', 0) > 0]
            if stubs:
                emit('split', {'files': stubs})
            seen = set()
            for f in doc['files']:
                key = f.get('sha') or ('occurrence', f['id'])
                if key in seen:
                    continue
                seen.add(key)
                emit('split', {'v': doc['v'], 'files': [f]})
    out.write('\\.\n')
    queries = []
    for codec in ('pglz', 'lz4'):
        for variant in ('v8', 'full', 'trimmed'):
            for layout in ('joined', 'split'):
                table = f'{schema}.{variant}_{layout}_{codec}'
                out.write(f'CREATE UNLOGGED TABLE {table}(sample text, doc jsonb COMPRESSION {codec});\n')
                out.write(f"INSERT INTO {table} SELECT sample, doc::text::jsonb FROM {schema}.staged WHERE variant='{variant}' AND layout='{layout}';\n")
                queries.append(f"SELECT '{codec}' codec, '{variant}' variant, '{layout}' layout, sample, count(*) records, sum(pg_column_size(doc)) payload_bytes FROM {table} GROUP BY sample")
    out.write('\\pset format csv\n')
    out.write('\\o '+str(root/'pg-payload.csv')+'\n')
    out.write(' UNION ALL '.join(queries)+' ORDER BY codec, sample, layout, variant;\n')
    out.write('\\o '+str(root/'pg-relations.csv')+'\n')
    out.write(f"SELECT relname, pg_total_relation_size(oid) total_bytes FROM pg_class WHERE relnamespace='{schema}'::regnamespace AND relkind='r' ORDER BY relname;\n")
    out.write('\\o\n')
    out.close()
    status = proc.wait()
    if status:
        raise SystemExit(status)


if __name__ == '__main__':
    main()
