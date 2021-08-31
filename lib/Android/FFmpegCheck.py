import os
from ..Base import Base
from ..info import Info
from ..apk import register

TITLE = 'FFMPEG arbitrary file reading detection'
LEVEL = 1
INFO = 'Detect whether there are any file reading vulnerabilities in the ffmpeg so library of the App'


class FFmpegCheck(Base):
    def scan(self):
        strline = 'find ' + self.appPath + ' -name *.so | grep "ffmpeg\|FFmpeg"'
        arr = os.popen(strline).readlines()
        versions = []
        result = ''
        for item in arr:
            strline = "strings  " + item[:-1] + " | grep 'FFmpeg version'"
            out = os.popen(strline).readlines()
            for line in out:
                if line.startswith('FFmpeg version'):
                    v = line[:-1]
                    if v not in versions:
                        versions.append(v)
                        filePath = '/'.join(item[:-1].split('/')[-2:])
                        result += filePath + ': ' + v + '\n'
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result=result).description()


register(FFmpegCheck)