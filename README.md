<div align="center">
    <h1>
        Web Fuzzer
    </h1>
    <h4><b>Web Dynamic Analysis Tool</b></h4>
    <h4>
        <a href="#install">Install</a>
        •
        <a href="#roadmap">Roadmap</a>
        •
        <a href="#contact">Contact</a>
        •
        <a href="#copyright">Copyright</a>
    </h4>
    
### ![chart](./test/example/dvwa/vulnerability_chart.png)

</div>

Our Web Fuzzer is consist of Grammar Fuzzer inside. 
Unlike dictionary based fuzzer, our payloads are more various and effective.

## Install
For now, our Web Fuzzer supports only Windows.

### python 3.10.11 by pyenv
you can skip this step if you have python 3.10.11 already.
```sh
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"; &"./install-pyenv-win.ps1"
pyenv install 3.10.11 
```

### install dependency

```sh 
pip install -r requirements.txt
```

### chrome

Chrome is neccessary! we use chrome for selenium webdriver inside.

### usage

First, set .env for your target that you want to investigate.
Then you can run command like below

```sh
python web_fuzzer/main.py
```

### how to config .env
- DVWA: this is for newcomers, only use with DVWA turn it "True" to use this.

options below works when DVWA set "False"
- BASE_URL: target base url
- LOGIN_URL: login url for target
- ID: test id
- PW: test password
- ID_INPUT_NAME: login input tag name attr value for ID 
- PW_INPUT_NAME: login input tag name attr value for PW 
- SUBMIT_INPUT_NAME: login input tag name attr value for login button

### DVWA
if you don't have any target for security testing, here's DVWA for you.

To do that, edit DEBUG value in `.env` file from `DVWA="False"` to `DVWA="True"`

```sh
docker pull vulnerables/web-dvwa
docker run -it -p 80:80 vulnerables/web-dvwa
```
and connect `localhost` in browser with login info

```sh
ID : admin
PW : password
```
after login, click `Create / Reset Database` button in [setup page](http://localhost/setup.php)

if you want to use this env after reboot, you can commit your docker container.

```sh
docker ps -all
docker commit [CONTAINER ID] vulnerables/web-dvwa
```

## Roadmap

- [ ] support linux (handling new window)
- [ ] folder path hardcorded -> dynamic path using os.path module

### Features

* Crawling urls from target with credential.
* Customize dictionary for Broken Access Control
* Detect vulnerabilities using GRAMMAR Fuzzer
    * Broken Access Control
    * Command Injection
    * Local File Inclusion
    * SQL Injection
    * XSS
* Generate HTML report

## Contact

If you need to get in-touch with me ([silvergun8291](https://github.com/silvergun8291) – lead developer), 

please do so at the following email address: sv5506829sv@gmail.com

## Copyright

Copyright © SWLAB@JNU 2023

---