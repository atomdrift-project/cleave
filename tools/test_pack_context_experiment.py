"""Boundary checks for the reversible layout experiment."""
import copy
import unittest

from pack_context_experiment import VARIANTS, pack, unpack, zencode


class ContextPacking(unittest.TestCase):
    def test_preserves_binary_gaps_empty_windows_captions_and_order(self):
        document = {"v": "file-1", "files": [{"ctx": [
            {"ln": 100, "b": zencode(b"\xff\x00abc"), "n": [[0, 101, 2, [4, "captured", 0.65]]], "w": 512},
            {"ln": 0, "b": "", "line": 1, "col": 1, "w": 10},
            {"ln": 999, "b": zencode(b"last")},
        ]}, {}, {"ctx": []}]}
        original = copy.deepcopy(document)
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                self.assertEqual(unpack(pack(document, variant)), original)
                self.assertEqual(document, original)

    def test_every_partial_z85_boundary(self):
        for a in range(9):
            for b in range(9):
                document = {"v": "file-1", "files": [{"ctx": [
                    {"ln": 0, "b": zencode(bytes(range(a)))},
                    {"ln": 100, "b": zencode(bytes(range(b)))},
                ]}]}
                for variant in VARIANTS:
                    self.assertEqual(unpack(pack(document, variant)), document)

    def test_bad_lengths_and_unconsumed_content_fail(self):
        for length in (-1, True, 4, 0, 1.5):
            candidate = {"v": "experiment-packed-tuples", "files": [{"ctx": {
                "b": zencode(b"abc"), "ranges": [[0, length]],
            }}]}
            with self.subTest(length=length), self.assertRaises(ValueError):
                unpack(candidate)

    def test_metadata_cannot_replace_evidence(self):
        candidate = {"v": "experiment-packed-tuples", "files": [{"ctx": {
            "b": zencode(b"abc"), "ranges": [[0, 3, {"b": ""}]],
        }}]}
        with self.assertRaises(ValueError):
            unpack(candidate)


if __name__ == "__main__":
    unittest.main()
