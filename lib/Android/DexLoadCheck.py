from ..Base import Base
from ..info import Info
from ..apk import register
from ..tools import *

TITLE = 'SDCARD loading dex detection'
LEVEL = 1
INFO = 'Detect whether there is a risk of dynamically loading dex from sdcard in the App program'


class DexLoadCheck(Base):
    def scan(self):
        strline = cmdString(
            'grep -r "Ldalvik/system/DexClassLoader;-><init>" ' + self.appPath)
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
                    if 'Ldalvik/system/DexClassLoader;-><init>' in line:
                        start = line.find('{') + 1
                        end = line.find('}')
                        vs = line[start:end]
                        v = vs.split(',')[1].strip()
                        for j in range(i, count):
                            ll = lines[j]
                            llnext = lines[j]
                            if j+1 < count:
                                llnext = lines[j+1]
                            if 'Landroid/os/Environment;->getExternalStorageDirectory' in ll:
                                if '.local' in llnext and v in llnext and 'Ljava/lang/String;' in llnext:
                                    result = name + ' : ' + str(count - i)
                                    if result not in results:
                                        results.append(result)
                                    break
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(DexLoadCheck)
