# Web Fuzzer - Web Dynamic Analysis Tool


# Installation


### Quick Start

```sh 
poetry env use 3.10
poetry install
poetry run start
```

### pyenv

```sh
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"; &"./install-pyenv-win.ps1"
pyenv install 3.10.11 
```

# Tutorial

### DVWA

```sh
docker pull vulnerables/web-dvwa
docker run -it -p 80:80 vulnerables/web-dvwa
```

### DVWA Login

```sh
ID : admin
PW : password
```

### Create Database

http://localhost/setup.php

Create / Reset Database:q:q:Qqqqqq