# Web Fuzzer - Web Dynamic Analysis Tool


# Installation


### Quick Start

```sh 
poetry env use 3.10
poetry install
poetry run start
```

### Chrome

Chrome is neccessary!

### pyenv

```sh
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pyenv-win/pyenv-win/master/pyenv-win/install-pyenv-win.ps1" -OutFile "./install-pyenv-win.ps1"; &"./install-pyenv-win.ps1"
pyenv install 3.10.11 
```

<br>

# Tutorial

### DVWA Pull

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

`Create / Reset Database`


### Docker Commit

```sh
docker ps -all
docker commit [CONTAINER ID] vulnerables/web-dvwa
```

### DVWA Start

```sh
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```



