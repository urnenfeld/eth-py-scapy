#!./virtualenv/env/bin/python
# File  : etest.py
# Who   : jamores
#
# Minimal infrastructure to execute test cases (autodiscover, autoinstantiation, autoexecution)
# - autodiscover : scan 'testcases' folder for all 'baseTest' subclasses
# - autoinstantiation : instantiate found subclasses
# - autoexecution : execute all functions compliant with r'^test.*'

import sys
import re
import os
import pkgutil
import importlib
import inspect
import pyclbr

import testcases
from testcases import test_base

TAB = "    "

class eTester:
    """ Minimal infrastructure to execute Ethernet test cases."""

    # test functions : those validating below regex
    TEST_REGEX = r'^test.*'

    def __init__(self):
        pass

    def run(self):
        """ discover, execute and present tests."""
        for testclazz in self._executeTests():
            self._presentTest(testclazz)

    def _executeTests(self):
        """ autodiscover test classes, execute test functions, yield class instance to gather results."""

        # 1.- Walk all modules within 'testcases' package
        # 2.- Import module, look for subclasses of 'baseTest'
        # 3.- Instantiate subclass, execute test functions
        for importer,modname,ispkg in pkgutil.walk_packages(path=testcases.__path__,prefix="testcases.",onerror=lambda x:None):
            if modname != "testcases.test_base":
                module = __import__(modname,fromlist="dummy")

                for name,obj in inspect.getmembers(module):
                    if inspect.isclass(obj):
                        if issubclass(obj,test_base.baseTest) and (name != "baseTest"):
                            test_class = getattr(module,name)()

                            # execute test functions
                            for method_name,method in inspect.getmembers(test_class,predicate=inspect.ismethod):
                                match = re.search(self.TEST_REGEX,method_name.lower())
                                if match:
                                    method()
                            yield test_class
                                
    def _presentTest(self,test):
        """ Present results of executed TestCases."""
        # NOTE : implementation provided as basic (non-optimal) example. Customize as per your needs!!

        self._presentTest_console(test)
        
    def _presentTest_console(self,test):
        print ""
        print "-"*len("Test category : "+test.category)
        print "Test category : "+test.category
        print "-"*len("Test category : "+test.category)

        # show quick summary (just test title)
        for msg in test.getErrors():
            print TAB+"[ERROR]".ljust(10,'.')+msg[0]
        for msg in test.getWarnings():
            print TAB+"[WARN]".ljust(10,'.')+msg[0]
        for msg in test.getOKs():
            print TAB+"[OK]".ljust(10,'.')+msg[0]

        # show details about failed tests
        if(test.hasErrors):
            print ""
            print TAB+"Error messages detail"
            for msg in test.getErrors():
                print TAB+"[ERROR]".ljust(10,'.')+msg[0]
                print "\n".join((2*TAB)+ i for i in msg[1].splitlines())

        # show details about warnings
        if(test.hasWarnings):
            print ""
            print TAB+"Warning messages detail"
            for msg in test.getWarnings():
                print TAB+"[WARN]".ljust(10,'.')+msg[0]
                print "\n".join((2*TAB)+ i for i in msg[1].splitlines())



if __name__ == '__main__':
    et = eTester()
    et.run()



