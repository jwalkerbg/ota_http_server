# test_utilities.py

import unittest
import pytest   # needed for pytest decorators


# unittest style
class TestUtils(unittest.TestCase):
    # unittest assertion
    def test_hello_from_utils(self):
        self.assertEqual("1","1")

    def test_hello_from_utils_failed(self):
        self.assertEqual("1","2")

class TestUtilsPytest:
    # pytest assertion
    def test_hello_from_utils_pytest(self):
        assert "1" == "1"

    #@pytest.mark.xfail(reason="demonstrating a failing test")
    def test_hello_from_utils_failed_pytest(self):
        assert "1" == "8"