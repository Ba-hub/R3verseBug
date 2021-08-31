from ..Base import Base
from ..info import Info
from ..apk import register
from ..tools import *

TITLE = 'Clipboard sensitive information leakage detection'
LEVEL = 2
INFO = 'Detect whether the app has the risk of sensitive data leakage on the clipboard'


class ClipboardCheck(Base):
    def scan(self):
        strline = cmdString('grep -r "ClipboardManager;->setPrimaryClip\|ClipboardManager;->setText" ' + self.appPath)
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
                    if 'ClipboardManager;->setPrimaryClip' in line or 'ClipboardManager;->setText' in line:
                        result = name + ' : ' + str(count - i)
                        if result not in results:
                            results.append(result)
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(ClipboardCheck)