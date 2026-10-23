"""Measure independent file-record compression, not PostgreSQL storage.

Uses the reversible transforms in measure_json3_design.py. Each input file
occurrence gets its own dictionary scope and zstd frame. Includes a common
parent-stub record, but does not emulate hopper's eligibility, upsert/dedup,
JSONB, indexes, TOAST, or historical version retention.
"""
import copy
import ctypes
import ctypes.util
import hashlib
import json
import os
import pathlib
import sys

import measure_json3_design as codec


def compressor():
    name = os.environ.get('JSON3_ZSTD_LIBRARY') or ctypes.util.find_library('zstd')
    if not name:
        raise RuntimeError('libzstd is required; set JSON3_ZSTD_LIBRARY to its path')
    lib = ctypes.CDLL(name)
    lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    lib.ZSTD_compressBound.restype = ctypes.c_size_t
    lib.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.ZSTD_compress.restype = ctypes.c_size_t
    lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
    lib.ZSTD_isError.restype = ctypes.c_uint

    def size(data):
        capacity = lib.ZSTD_compressBound(len(data))
        dest = ctypes.create_string_buffer(capacity)
        result = lib.ZSTD_compress(dest, capacity, data, len(data), 3)
        if lib.ZSTD_isError(result):
            raise RuntimeError('zstd compression failed')
        return result
    return size


def main():
    zsize = compressor()
    for path in map(pathlib.Path, sys.argv[1:]):
        data = path.read_bytes()
        report = json.loads(data)
        report = report.get('raw', report)
        assert report.get('v') == '8'
        totals = {v: dict(raw=0, zstd3=0) for v in
                  ('v8', 'traits', 'symbols_context', 'all')}
        regressions = {v: 0 for v in totals if v != 'v8'}
        parent_keys = {'id', 'sha', 'path', 'type', 'depth', 'size', 'risk', 'mol'}
        stubs = [{k: v for k, v in f.items() if k in parent_keys}
                 for f in report['files'] if f.get('depth', 0) > 0]
        # Common placement/reference overhead; heavy root data counted below.
        if stubs:
            common = codec.wire({'files': stubs})
            for total in totals.values():
                total['raw'] += len(common)
                total['zstd3'] += zsize(common)
        for f in report['files']:
            for ctx in f.get('ctx', []):
                ctx.pop('n', None)
            base = {'v': '8', 'files': [f]}
            if 'rev' in report:
                base['rev'] = report['rev']
            base_zstd = None
            for variant, total in totals.items():
                d = copy.deepcopy(base)
                if variant in ('traits', 'all'):
                    codec.traits_encode(d)
                if variant in ('symbols_context', 'all'):
                    codec.symbols_encode(d, 'report')
                    codec.context_encode(d)
                if variant == 'all':
                    codec.metrics_encode(d)
                encoded = codec.wire(d)
                compressed = zsize(encoded)
                total['raw'] += len(encoded)
                total['zstd3'] += compressed
                if variant == 'v8':
                    base_zstd = compressed
                else:
                    regressions[variant] += compressed > base_zstd
                decoded = json.loads(encoded)
                if variant == 'all':
                    codec.metrics_decode(decoded)
                if variant in ('symbols_context', 'all'):
                    codec.context_decode(decoded)
                    codec.symbols_decode(decoded, 'report')
                if variant in ('traits', 'all'):
                    codec.traits_decode(decoded)
                assert decoded == base, (path, f.get('id'), variant)
        print(json.dumps(dict(sample=path.name,
                              input_sha256=hashlib.sha256(data).hexdigest(),
                              records=len(report['files']),
                              distinct_shas=len({f.get('sha') for f in report['files']}),
                              parent_stubs=len(stubs), variants=totals,
                              compressed_regression_records=regressions)), flush=True)


if __name__ == '__main__':
    main()
