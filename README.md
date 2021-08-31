<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/Ba-hub/R3verseBug.git">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Android Reverse Engeneering Framework</h3>

<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

Reverse engineering is the process of taking an app apart to find out how it works,whether it’s a physical object such as a lock or in this case,a mobile application.Decompiling is a form of reverse engineering in which a mobile app is analyzed by looking at its source code. A decompiler program examines the binary and translates its contents from a low-level abstraction to a higher-level abstraction.You can do this by examining the compiled app(static analysis), observing the app during runtime (dynamic analysis),or a combination of both.

An Android binary is called an APK, which stands for Android Package Kit.The APK contains application data in the form of zipped Dalvik Executable (.dex) files.

DEX files consist of the following components:

File Header
String Table
Class List
Field Table
Method Table
Class Definition Table
Field List
Method List
Code Header
Local Variable List

### Built With

* [Python3]
* [C & C++]
* [Shell Script]


<!-- GETTING STARTED -->
## Getting Started

Hare is Available Two Binary File R3verseBug (For Kali,Ubantu,Debian Base Distribution) & ter-R3verseBug (Termux)

In This Programs uses Two Different type of Scan 1st Level & 2nd Level, 2nd Level Scaning Not Supported In Termux!

### Prerequisites 
* python3-pip
  ```
  apt install python3-pip
  ```
* python-pip
  ```
  apt install python-pip
  ```
* apktool  
  ```
  apt install apktool 
  ```
* apksigner 
  ```
  apt install apksigner
  ``` 
* unzip
  ```
  apt install unzip
  ```
* aapt 
  ```
  apt install aapt
  ```
* jadx
  ```
  apt install jadx 
  ```
* dex2jar
  ```
  apt install dex2jar
  ```
* dexdump 
  ```
  apt install dexdump
  ```
### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/Ba-hub/R3verseBug.git
   ```
2. Give Executable Permission 

* For Kali Linux,Ubantu, Debian

   ```
   chmod +x R3verseBug
   
   ./R3verseBug
   
   ```
*  For Termux 
   ```
   chmod +x ter-R3verseBug

   ./ter-R3verseBug
   
   ```

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

```

Made By ~ Ghosthub

```

