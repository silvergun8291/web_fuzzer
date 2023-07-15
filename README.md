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
</div>

### ![chart](./test/example/dvwa/vulnerability_chart.png)
<div align="center">
    <table>
        <tr>
        <th>Vulnerability</th>
        <th>Count</th>
        </tr>
        <tr>
        <td>Broken Access Control</td>
        <td>3</td>
        </tr>
        <tr>
        <td>Command Injection</td>
        <td>1</td>
        </tr>
        <tr>
        <td>Local File Inclusion</td>
        <td>1</td>
        </tr>
        <tr>
        <td>SQL Injection</td>
        <td>1</td>
        </tr>
        <tr>
        <td>Cross-site scripting</td>
        <td>3</td>
        </tr>
        <tr>
        <td colspan='4' style='text-align: right;'>
            <b>Total:</b> 9
        </td>
        </tr>
    </table>
</div>

The [Triumph Mayflower Club](https://www.triumphmayflowerclub.com/) is an organisation dedicated to the preservation of classic 1950s car, the Mayflower, by British car manufacturer Triumph. The club itself formed in 1974 and made its initial, limited foray into the World Wide Web back in [2005](https://legacy.triumphmayflowerclub.com/), and then I ([Andi](https://www.github.com/andiemmadavies), project maintainer) was commissioned in 2017 to create them a new website from scratch when my parents became members. Click [here](https://www.triumphmayflowerclub.com/about) if you’re interested in reading more about the car and the club.

This new website is written in vanilla [HTML5](https://developer.mozilla.org/docs/web/html) for the documents’ markup, [CSS3](https://developer.mozilla.org/docs/web/css) for styling, a small amount of [JavaScript](https://developer.mozilla.org/docs/web/javascript) ([ES6](https://developer.mozilla.org/docs/web/javascript/language_resources)) and is built using [Jekyll](https://www.jekyllrb.com/) as a static site generator to minimise code duplication. It is designed to run in any major “evergreen” browser (i.e. Chromium-based [Microsoft Edge](https://www.microsoft.com/edge), [Google Chrome](https://www.google.co.uk/chrome), [Mozilla Firefox](https://www.mozilla.org/firefox), [Apple Safari](https://www.apple.com/safari) or [Opera](https://www.opera.com/)), desktop or mobile, without issue.

---
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



