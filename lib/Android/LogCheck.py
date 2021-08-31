from ..Base import Base
from ..info import Info
from ..tools import *
from ..apk import register

TITLE = 'Log leakage risk detection'
LEVEL = 1
INFO = 'Detect whether there is a risk of log leakage in Apk, focusing on detecting the Log and print functions'


class LogCheck(Base):
    def scan(self):
        strline = cmdString('grep -r "Landroid/util/Log\|Ljava/io/PrintStream" ' + self.appPath)
        paths = getSmalis(os.popen(strline).readlines())
        results = []
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                index = 0
                name = getFileName(path)
                for line in lines:
                    index += 1
                    if 'Landroid/util/Log;->d' in line or 'Landroid/util/Log;->v' in line or 'Ljava/io/PrintStream;->print' in line:
                        result = name + ' : ' + str(index)
                        if result not in results:
                            results.append(result)
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(LogCheck)