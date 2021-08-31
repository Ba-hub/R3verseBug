from ..Base import Base
from ..info import Info
from ..apk import register
from ..tools import *

TITLE = 'JS resource file leak detection'
LEVEL = 1
INFO = 'Detect whether there is a risk of JS file information leakage in Apk'


class JSCheck(Base):
    def scan(self):
        strline = cmdString("find " + self.appPath + " -name '*.js'")
        out = os.popen(strline).readlines()
        jsfiles = []
        for line in out:
            filepath = line[:-1]
            if filepath not in jsfiles:
                jsfiles.append(filepath)
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(jsfiles)).description()


register(JSCheck)