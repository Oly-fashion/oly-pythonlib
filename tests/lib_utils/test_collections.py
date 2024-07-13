import pytest

from src.lib_utils.collections import chunks


class TestChunk:
    def test_empty_list(self):
        with pytest.raises(StopIteration):
            chunks([], 1).__next__()

    def test_chunk_size_1(self):
        results = []

        for c_num, total_chunks, chunk in chunks([1, 2, 3], 1):
            results.append((c_num, total_chunks, chunk))

        assert results == [(1, 3, [1]), (2, 3, [2]), (3, 3, [3])]

    def test_chunk_size_2(self):
        results = []

        for c_num, total_chunks, chunk in chunks([1, 2, 3, 4, 5], 2):
            results.append((c_num, total_chunks, chunk))

        assert results == [(1, 3, [1, 2]), (2, 3, [3, 4]), (3, 3, [5])]

    def test_chunk_size_0(self):
        with pytest.raises(ValueError):
            chunks([1, 2, 3], 0).__next__()
