# File  : test_example
# Who   : jamores
# Example file how to create TestCases

from test_base import baseTest

class test_example(baseTest):

    def __init__(self):
        # call superclass constructor providing test collection category
        baseTest.__init__(self,"example")

    # Test 00 : description
    def test_00(self):
        """ some test."""
        msg = ""

        # test something here

        msg = "this is the test result message, in case there's something\nto report more than just the test description"

        # log test results
        self.addTestCase("test one-liner",error=msg)
