from ..Base import Base
from ..info import Info
from ..tools import *
from ..apk import register

TITLE = 'PendingIntent wrong use of Intent risk detection'
LEVEL = 1
INFO = 'Detect whether there is a risk of PendingIntent using implicit Intent or empty Intent in App'


class PendingIntentCheck(Base):
    def scan(self):
        strline = cmdString('grep -r "Landroid/app/PendingIntent;" ' + self.appPath)
        paths = getSmalis(os.popen(strline).readlines())
        results = []
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                lines.reverse()
                index = 0
                count = len(lines)
                name = getFileName(path)
                for line in lines:
                    if 'Landroid/app/PendingIntent;->get' in line and 'Landroid/content/Intent;' in line:
                        v = line.strip().split(',')[2].replace(' ', '')
                        for i in range(index, count):
                            s = lines[i]
                            if v in s:
                                if 'Landroid/content/Intent;->setAction' in s or \
                                        'Landroid/content/Intent;->setClass' in s or \
                                        'Landroid/content/Intent;->setClassName' in s or \
                                        'Landroid/content/Intent;->setComponent' in s or \
                                        'Landroid/content/Intent;->setPackage' in s or \
                                        'Landroid/content/Intent;-><init>(Ljava/lang/String;)V' in s:
                                    break
                                if 'Landroid/content/Intent;-><init>()V' in s:
                                    result = name + ' : ' + str(count - index)
                                    if result not in results:
                                        results.append(result)
                                    break
                    index += 1
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


register(PendingIntentCheck)