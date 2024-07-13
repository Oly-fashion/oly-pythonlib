from src.lib_utils.extract import Extractor


class TestExtractorStr:
    def test_good_string(self):
        extractor = Extractor.create_extractor(str)
        assert extractor("test") == "test"

    def test_empty_string(self):
        extractor = Extractor.create_extractor(str)
        assert extractor("") is None

    def test_none_string(self):
        extractor = Extractor.create_extractor(str)
        assert extractor(None) is None


class TestExtractorBool:
    def test_good_bool(self):
        extractor = Extractor.create_extractor(bool)
        assert extractor(True) is True
        assert extractor(False) is False

    def test_good_string(self):
        extractor = Extractor.create_extractor(bool)
        assert extractor("true") is True
        assert extractor("false") is False
        assert extractor("True") is True
        assert extractor("False") is False

    def test_empty_string(self):
        extractor = Extractor.create_extractor(bool)
        assert extractor("") is False
        assert extractor(" ") is False
        assert extractor("  ") is False

    def test_none_string(self):
        extractor = Extractor.create_extractor(bool)
        assert extractor(None) is False


class TestExtractInt:
    def test_good_int(self):
        extractor = Extractor.create_extractor(int)
        assert extractor(1) == 1

    def test_good_string(self):
        extractor = Extractor.create_extractor(int)
        assert extractor("1") == 1

    def test_empty_string(self):
        extractor = Extractor.create_extractor(int)
        assert extractor("") is None

    def test_none_string(self):
        extractor = Extractor.create_extractor(int)
        assert extractor(None) is None


class TestExtractFloat:
    def test_good_float(self):
        extractor = Extractor.create_extractor(float)
        assert extractor(1.1) == 1.1

    def test_good_string(self):
        extractor = Extractor.create_extractor(float)
        assert extractor("1.1") == 1.1

    def test_empty_string(self):
        extractor = Extractor.create_extractor(float)
        assert extractor("") is None

    def test_none_string(self):
        extractor = Extractor.create_extractor(float)
        assert extractor(None) is None
