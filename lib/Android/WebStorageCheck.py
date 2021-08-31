from ..Base import Base
from ..info import Info
from ..apk import register
from ..tools import *

TITLE = 'WEB STORAGE data leakage detection'
LEVEL = 1
INFO = 'Detect whether the App has the risk of Web Storage data leakage'


class WebStorageCheck(Base):
    def scan(self):
        strline = cmdString("find " + self.appPath + " -name '*.js'")
        out = os.popen(strline).readlines()
        jsfiles = []
        for line in out:
            filepath = line[:-1]
            if filepath not in jsfiles:
                jsfiles.append(filepath)
        files = jsBeautify(jsfiles)
        results = []
        for item in files:
            with open(item, 'r') as f:
                io = f.read()
                s = str(io)
                if 'localStorage' in s or 'sessionStorage' in s:
                    results += item.replace('1.js', '.js')
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result=''.join(results)).description()


register(WebStorageCheck)