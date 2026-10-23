"""Split-record JSONB experiment; run only against a disposable PostgreSQL DB.

Usage: python3 tools/measure_json3_pg.py UNIX_SOCKET_DIR PORT REPORT...
Creates schema json3bench (fails if it already exists). Does not alter hopper.
Deduplicates each report by SHA using its first occurrence, retains a shared
placement-stub record, and compares pglz/lz4 payload and total relation sizes.
This is a storage microbenchmark, not hopper's complete ingestion policy.
"""
import copy
import json
import pathlib
import subprocess
import sys

import measure_json3_design as codec


def field(s):
    return s.replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n').replace('\r', '\\r')


def main():
    socket, port, *paths = sys.argv[1:]
    assert pathlib.Path(socket).is_dir()
    assert port.isdigit()
    proc = subprocess.Popen(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-h', socket,
                             '-p', port, '-d', 'postgres'], stdin=subprocess.PIPE,
                            text=True)
    out = proc.stdin
    out.write('CREATE SCHEMA json3bench;\n')
    out.write('CREATE UNLOGGED TABLE json3bench.staged(sample text, variant text, doc jsonb);\n')
    out.write('COPY json3bench.staged FROM STDIN;\n')
    variants = ('v8', 'traits', 'symbols_context', 'all')
    for path in map(pathlib.Path, paths):
        report = json.loads(path.read_bytes())
        report = report.get('raw', report)
        assert report.get('v') == '8'
        stub_keys = {'id', 'sha', 'path', 'type', 'depth', 'size', 'risk', 'mol'}
        stubs = [{k: v for k, v in f.items() if k in stub_keys}
                 for f in report['files'] if f.get('depth', 0) > 0]
        if stubs:
            for variant in variants:
                encoded = codec.wire({'files': stubs}).decode()
                out.write('\t'.join(map(field, (path.name, variant, encoded)))+'\n')
        seen = set()
        for i, f in enumerate(report['files']):
            key = f.get('sha') or ('occurrence', i)
            if key in seen:
                continue
            seen.add(key)
            for ctx in f.get('ctx', []):
                ctx.pop('n', None)
            base = {'v': '8', 'files': [f]}
            if 'rev' in report:
                base['rev'] = report['rev']
            for variant in variants:
                d = copy.deepcopy(base)
                if variant in ('traits', 'all'):
                    codec.traits_encode(d)
                if variant in ('symbols_context', 'all'):
                    codec.symbols_encode(d, 'report')
                    codec.context_encode(d)
                    # PostgreSQL text cannot represent U+0000; keep exact bytes.
                    for row in d['files'][0].get('c', []):
                        if row[1] == 0 and '\0' in row[2]:
                            row[1], row[2] = 1, codec.zencode(row[2].encode())
                if variant == 'all':
                    codec.metrics_encode(d)
                encoded = codec.wire(d).decode()
                out.write('\t'.join(map(field, (path.name, variant, encoded)))+'\n')
                # Keep the JSONB-specific adaptation covered by a round trip.
                decoded = json.loads(encoded)
                if variant == 'all':
                    codec.metrics_decode(decoded)
                if variant in ('symbols_context', 'all'):
                    codec.context_decode(decoded)
                    codec.symbols_decode(decoded, 'report')
                if variant in ('traits', 'all'):
                    codec.traits_decode(decoded)
                assert decoded == base
    out.write('\\.\n')
    queries = []
    for compression in ('pglz', 'lz4'):
        for variant in variants:
            table = f'json3bench.{variant}_{compression}'
            out.write(f'CREATE UNLOGGED TABLE {table}(sample text, doc jsonb COMPRESSION {compression});\n')
            # Force a fresh JSONB datum, so existing TOAST compression is not reused.
            out.write(f"INSERT INTO {table} SELECT sample, doc::text::jsonb FROM json3bench.staged WHERE variant='{variant}';\n")
            queries.append(f"SELECT '{compression}' codec, '{variant}' variant, sample, count(*) records, sum(pg_column_size(doc)) payload_bytes FROM {table} GROUP BY sample")
    out.write('\\pset format csv\n')
    out.write('\\o '+socket+'/payload.csv\n')
    out.write(' UNION ALL '.join(queries)+' ORDER BY codec, sample, variant;\n')
    out.write('\\o '+socket+'/relations.csv\n')
    out.write("SELECT relname, pg_total_relation_size(oid) total_bytes FROM pg_class WHERE relnamespace='json3bench'::regnamespace AND relkind='r' ORDER BY relname;\n")
    out.write('\\o\n')
    out.close()
    status = proc.wait()
    if status:
        raise SystemExit(status)


if __name__ == '__main__':
    main()
