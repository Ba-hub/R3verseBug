from ..Base import Base
from ..info import Info
from ..apk import register
from ..tools import *

TITLE = 'Arbitrary read and write detection of database files'
LEVEL = 2
INFO = 'Detect whether there is any risk of reading and writing database files in the App'


class DBCheck(Base):
    def scan(self):
        strline = cmdString('grep -r "Landroid/content/Context;->openOrCreateDatabase" ' + self.appPath)
        paths = getSmalis(os.popen(strline).readlines())
        results = []
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                lines.reverse()
                count = len(lines)
                name = getFileName(path)
                for i in range(0, count):
                    line = lines[i]
                    if 'Landroid/content/Context;->openOrCreateDatabase' in line:
                        v = line.split(',')[2]
                        for j in range(i, count):
                            ll = lines[j]
                            if 'const/4' in ll and v in ll:
                                value = ll.strip().split(' ')[-1]
                                if value != '0x0':
                                    result = name + ' : ' + str(count - i)
                                    if result not in results:
                                        results.append(result)
                                break
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(DBCheck)