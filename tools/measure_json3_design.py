"""Design experiment only: reversible v8 transforms, not a production codec."""
import collections
import copy
import hashlib
import json
import pathlib
import statistics
import subprocess
import sys
import time


def wire(x):
    return json.dumps(x, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def trim(row):
    while row and row[-1] is None:
        row.pop()
    return row


class Pool:
    def __init__(self):
        self.rows, self.index = [], {}

    def add(self, row):
        key = wire(row)
        if key not in self.index:
            self.index[key] = len(self.rows)
            self.rows.append(row)
        return self.index[key]


def traits_encode(d):
    p = Pool()
    for f in d['files']:
        if 'traits' not in f:
            continue
        rows = []
        for t in f.pop('traits'):
            # Preserve presence and all dynamic/unknown fields exactly.
            static = {k: t[k] for k in ('id', 'desc', 'mbc', 'atk') if k in t}
            rest = {k: v for k, v in t.items() if k not in static and k not in ('crit', 'conf')}
            rows.append([p.add(static), t['crit'], t['conf']] + ([rest] if rest else []))
        f['t'] = rows
    d['d'] = p.rows


def traits_decode(d):
    p = d.pop('d')
    for f in d['files']:
        if 't' in f:
            f['traits'] = [dict(p[r[0]], crit=r[1], conf=r[2], **(r[3] if len(r) > 3 else {})) for r in f.pop('t')]


def symbol_slots(files):
    for f in files:
        facts = f.get('facts', {})
        for kind, positions in [('imp', (0, 1)), ('exp', (0, 1)), ('funcs', (0, 2)), ('sec', (0, 4))]:
            for row in facts.get(kind, []):
                for i in positions:
                    if len(row) > i and row[i] is not None:
                        yield row, i
        for kind in ('tgt', 'mbr'):
            rows = facts.get(kind, [])
            for i in range(len(rows)):
                yield rows, i
        for s in f.get('supp', []):
            yield s, 'id'
            for leg in s.get('by', []):
                yield leg, 'id'


def symbols_encode(d, scope):
    groups = [(d, d['files'])] if scope == 'report' else [(f, [f]) for f in d['files']]
    for holder, files in groups:
        counts = collections.Counter(row[i] for row, i in symbol_slots(files))
        pool = []
        ids = {}
        # Deterministic first occurrence; conservative accounting for table commas.
        for s, n in counts.items():
            cost = len(wire(s))
            digits = len(str(len(pool)))
            if n * (cost - digits) > cost + 2:
                ids[s] = len(pool)
                pool.append(s)
        if pool:
            holder['s'] = pool
            for row, i in symbol_slots(files):
                if row[i] in ids:
                    row[i] = ids[row[i]]


def symbols_decode(d, scope):
    groups = [(d, d['files'])] if scope == 'report' else [(f, [f]) for f in d['files']]
    for holder, files in groups:
        pool = holder.pop('s', [])
        for row, i in symbol_slots(files):
            if isinstance(row[i], int):
                row[i] = pool[row[i]]


def metrics_encode(d):
    shapes = Pool()
    def flatten(obj, path=()):
        for k, v in obj.items():
            p = (*path, k)
            if isinstance(v, dict) and v:
                yield from flatten(v, p)
            else:
                yield list(p), v
    for f in d['files']:
        facts = f.get('facts', {})
        if 'metrics' not in facts:
            continue
        pairs = list(flatten(facts.pop('metrics')))
        facts['m'] = [shapes.add([p for p, v in pairs]), [v for p, v in pairs]]
    d['m'] = shapes.rows


def metrics_decode(d):
    shapes = d.pop('m')
    for f in d['files']:
        facts = f.get('facts', {})
        if 'm' not in facts:
            continue
        shape, values = facts.pop('m')
        obj = {}
        for path, value in zip(shapes[shape], values):
            target = obj
            for k in path[:-1]:
                target = target.setdefault(k, {})
            target[path[-1]] = value
        facts['metrics'] = obj


ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
DIGITS = {s: i for i, s in enumerate(ALPHABET)}


def zdecode(s):
    out = bytearray()
    for i in range(0, len(s), 5):
        group = s[i:i+5]
        v = 0
        for c in group + ALPHABET[-1] * (5-len(group)):
            v = v * 85 + DIGITS[c]
        out.extend(v.to_bytes(4, 'big')[:len(group)-1])
    return bytes(out)


def zencode(b):
    out = ''
    for i in range(0, len(b), 4):
        group = b[i:i+4]
        v = int.from_bytes(group.ljust(4, b'\0'), 'big')
        digits = ''
        for _ in range(5):
            v, r = divmod(v, 85)
            digits = ALPHABET[r] + digits
        out += digits[:len(group)+1]
    return out


def context_encode(d):
    for f in d['files']:
        if 'ctx' not in f:
            continue
        rows = []
        for c in f.pop('ctx'):
            other = {k: v for k, v in c.items() if k not in ('ln', 'b')}
            data, enc = c['b'], 1
            try:
                txt = zdecode(data).decode('utf-8')
                if len(wire(txt)) < len(wire(data)):
                    data, enc = txt, 0
            except (UnicodeError, OverflowError, KeyError):
                pass
            rows.append([c['ln'], enc, data] + ([other] if other else []))
        f['c'] = rows


def context_decode(d):
    for f in d['files']:
        if 'c' in f:
            f['ctx'] = [dict(ln=r[0], b=zencode(r[2].encode()) if r[1] == 0 else r[2], **(r[3] if len(r)>3 else {})) for r in f.pop('c')]


def zsize(b):
    return len(subprocess.run(['zstd', '-q', '-3', '-c'], input=b, stdout=subprocess.PIPE, check=True).stdout)


def parse_ms(b):
    ts = []
    for _ in range(3):
        start = time.perf_counter()
        x = json.loads(b)
        ts.append((time.perf_counter()-start)*1000)
        del x
    return round(statistics.median(ts), 2)


def main():
    for path in map(pathlib.Path, sys.argv[1:]):
        original = json.loads(path.read_bytes())
        original = original.get('raw', original)
        assert original.get('v') == '8'
        # Baseline already includes current notes removal; normalize older snapshots.
        for f in original['files']:
            for c in f.get('ctx', []):
                c.pop('n', None)
        b = wire(original)
        result = dict(sample=path.name, input_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), files=len(original['files']), variants={})
        result['variants']['v8'] = dict(raw=len(b), zstd3=zsize(b), parse_ms=parse_ms(b))
        for variant, scope, extra in [('traits', None, False), ('local_strings', 'file', True), ('report_strings', 'report', True)]:
            d = copy.deepcopy(original)
            start = time.perf_counter()
            traits_encode(d)
            if scope:
                symbols_encode(d, scope)
            if extra:
                metrics_encode(d)
                context_encode(d)
            transform_ms = (time.perf_counter()-start)*1000
            b = wire(d)
            result['variants'][variant] = dict(raw=len(b), zstd3=zsize(b), parse_ms=parse_ms(b), transform_ms=round(transform_ms, 2))
            # Verify actual serialized form, not only the in-memory transform.
            d = json.loads(b)
            if extra:
                context_decode(d)
                metrics_decode(d)
            if scope:
                symbols_decode(d, scope)
            traits_decode(d)
            assert d == original, (path, variant)
            del d
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
