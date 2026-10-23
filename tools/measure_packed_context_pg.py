"""Measure native JSONB/TOAST for pack_context_experiment.py outputs.

Usage: python3 tools/measure_packed_context_pg.py CASE_DIRECTORY SOCKET PORT
Uses a fresh schema in a disposable local database; no production connection.
"""
import json
import pathlib
import subprocess
import sys

from measure_context_retention_pg import field
from pack_context_experiment import VARIANTS, wire


def main():
    directory, socket, port = sys.argv[1:]
    root = pathlib.Path(directory)
    if not pathlib.Path(socket).is_dir() or not port.isdigit():
        raise ValueError("expected an explicit local socket and port")
    sql = ["CREATE SCHEMA packed_context;",
           "CREATE UNLOGGED TABLE packed_context.staged(sample text, variant text, doc jsonb);",
           "COPY packed_context.staged FROM STDIN;"]
    for case in sorted(root.iterdir()):
        if not case.is_dir() or not (case / "baseline.min.json").exists():
            continue
        for variant in ("baseline", *VARIANTS):
            doc = json.loads((case / (variant + ".min.json")).read_bytes())
            # Compare the representation, excluding experiment-label length.
            doc["v"] = "file-1"
            sql.append("\t".join(map(field, (case.name, variant, wire(doc).decode()))))
    sql.append("\\.")
    queries = []
    for codec in ("pglz", "lz4"):
        table = "packed_context." + codec
        sql.extend([
            f"CREATE UNLOGGED TABLE {table}(sample text, variant text, doc jsonb COMPRESSION {codec});",
            f"INSERT INTO {table} SELECT sample, variant, doc::text::jsonb FROM packed_context.staged;",
        ])
        queries.append(f"SELECT sample,variant,'{codec}' codec,pg_column_size(doc) payload_bytes FROM {table}")
    sql.extend(["\\pset format csv", "\\o " + str(root / "pg-payload.csv"),
                " UNION ALL ".join(queries) + " ORDER BY sample,codec,variant;", "\\o"])
    subprocess.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", socket,
                    "-p", port, "-d", "postgres"], input="\n".join(sql) + "\n", text=True, check=True)


if __name__ == "__main__":
    main()
