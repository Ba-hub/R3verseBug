from ..Base import Base
from ..info import Info
from ..apk import register
from ..tools import *

TITLE = 'IP leak detection'
LEVEL = 1
INFO = 'Detect the leaked IP of App'


class IPCheck(Base):
    def scan(self):
        strline = cmdString("grep -r -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' " + self.appPath)
        out = os.popen(strline).readlines()
        ips = []
        for item in out:
            if 'Binary file' in item or '0.0.0.0' in item:
                continue
            ip = item.strip().split(':')[-1]
            arr = str(ip).split('.')
            if arr[0].startswith('0') and len(arr[0]) > 1 \
                    or arr[1].startswith('0') and len(arr[1]) > 1 \
                    or arr[2].startswith('0') and len(arr[2]) > 1 \
                    or arr[3].startswith('0') and len(arr[3]) > 1:
                continue
            # Exclude the ones that start with less than 10, the most likely is the version number, not the IP 
            if len(arr[0]) == 1 and int(arr[0]) < 10:
                continue
            # Exclude the addresses beginning with 255 and ignore the mask address
            if len(arr[0]) == 3 and int(arr[0]) == 255:
                continue
            if ip not in ips:
                ips.append(ip)
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(ips)).description()


register(IPCheck)