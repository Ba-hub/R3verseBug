from ..Base import Base
from ..info import Info
from ..apk import register
from ..tools import *

TITLE = 'WebView security detection'
LEVEL = 1
INFO = 'Check whether the App program WebView is at risk'


class WebViewCheck(Base):
    def scan(self):
        strline = cmdString(
            'grep -r "Landroid/webkit/WebView" ' + self.appPath)
        paths = getSmalis(os.popen(strline).readlines())
        resultsPassword = []
        resultsCert = []
        resultsRCE = []
        resultsDebug = []
        resultsHidden = []
        for path in paths:
            with open(path, 'r') as f:
                lines = f.readlines()
                count = len(lines)
                name = getFileName(path)
                hasExp = True
                vvv = 3
                for i in range(0, count):
                    line = lines[i]
                    
                    if 'Landroid/webkit/SslErrorHandler;->proceed()V' in line:
                        result = name + ' : ' + str(i + 1)
                        if result not in resultsCert:
                            resultsCert.append(result)
                    
                    if 'Landroid/webkit/WebView;->addJavascriptInterface' in line:
                        result = name + ' : ' + str(i + 1)
                        if result not in resultsRCE:
                            resultsRCE.append(result)
                lines.reverse()
                for i in range(0, count):
                    line = lines[i]
                    
                    if 'Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V' in line:
                        start = line.find("{") + 1
                        end = line.find("}")
                        v = line[start:end]
                        for j in range(i, count):
                            ll = lines[j]
                            if v in ll and '0x1' in ll and 'const' in ll:
                                result = name + ' : ' + str(count - i)
                                if result not in resultsDebug:
                                    resultsDebug.append(result)
                                break
                    
                    if 'Landroid/webkit/WebView;->removeJavascriptInterface' in line:
                        start = line.find("{") + 1
                        end = line.find("}")
                        v = line[start:end].split(', ')[-1]
                        for j in range(i, count):
                            if vvv == 0:
                                break
                            ll = lines[j]
                            if v in ll:
                                if 'searchBoxJavaBridge_' in ll:
                                    vvv -= 1
                                if 'accessibility' in ll:
                                    vvv -= 1
                                if 'accessibilityTraversal' in ll:
                                    vvv -= 1
                        if vvv > 0 and name not in resultsHidden:
                            resultsHidden.append(name)
                    
                    if 'Landroid/webkit/WebSettings;->setSavePassword' in line:
                        start = line.find("{") + 1
                        end = line.find("}")
                        v = line[start:end].split(', ')[-1]
                        for j in range(i, count):
                            ll = lines[j]
                            if v in ll and 'const' in ll and '0x0' in ll:
                                hasExp = False
                                break
                        result = name + ' : ' + str(count - i)
                        if hasExp and result not in resultsPassword:
                            resultsPassword.append(result)
        Info(key=self.__class__, title='WebView plaintext storage password detection', level=1, info='Detect whether the App program has the risk of WebView storing passwords in plain text',
             result='\n'.join(resultsPassword)).description()
        Info(key=self.__class__, title='Webview bypasses certificate verification vulnerability', level=1, info='Check whether the Webview component of the App application continues to load the page after finding the https webpage certificate error',
             result='\n'.join(resultsCert)).description()
        Info(key=self.__class__, title='WebView remote code execution detection', level=3, info='Detect whether there is a remote code execution vulnerability in the Webview component of the App application',
             result='\n'.join(resultsRCE)).description()
        Info(key=self.__class__, title='WebView remote debugging detection', level=2, info='Detect whether there is a risk of Webview remote debugging in the App program',
             result='\n'.join(resultsDebug)).description()
        Info(key=self.__class__, title='WebView did not remove the risky system hidden interface vulnerabilities', level=2, info='Check whether there is an unremoved hidden interface of the Webview system in the App program',
             result='\n'.join(resultsHidden)).description()


register(WebViewCheck)
