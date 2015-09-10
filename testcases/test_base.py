# File  : test_base.py
# Who   : jamores
# Base clase for TestCases

class baseTest:
    """base test class."""
    LOG_OK,LOG_ERROR,LOG_WARN = range(3)


    def __init__(self,category):
        self.category = category
        self.ok_log = []        # list of tuples (title,msg)
        self.error_log = []     # list of tuples (title,msg)
        self.warning_log = []   # list of tuples (title,msg)

    def addTestCase(self,title,error=None,warning=None):
        """ Add test case to collection, classifying in ERROR,WARN or OK."""
        if((error != None) and (error != "")):
            self._addLog(baseTest.LOG_ERROR,title,error)
        elif((warning != None) and (warning != "")):
            self._addLog(baseTest.LOG_WARN,title,warning)
        else:
            self._addLog(baseTest.LOG_OK,title,"")

    def _addLog(self,logtype,title,msg):
        if(logtype == baseTest.LOG_WARN):
            self.warning_log.append((title,msg))
        elif( logtype == baseTest.LOG_ERROR):
            self.error_log.append((title,msg))
        elif( logtype == baseTest.LOG_OK):
            self.ok_log.append((title,msg))

    @property
    def hasErrors(self):
        """ Test class run without detecting errors?."""
        return(len(self.error_log) is not 0)
    
    @property
    def hasWarnings(self):
        """ Test class run without detecting warnings?."""
        return(len(self.warning_log) is not 0)

    def getErrors(self):
        for i in self.error_log:
            yield(i)
    def getWarnings(self):
        for i in self.warning_log:
            yield(i)
    def getOKs(self):
        for i in self.ok_log:
            yield(i)
                


