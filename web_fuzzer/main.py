import time
import json
import re
import os
import webbrowser
from tqdm import tqdm
from crawler import crawler
from vulnerabilities import xss
from vulnerabilities import sql_injection
from vulnerabilities import command_injection
from vulnerabilities import broken_access_control
from vulnerabilities import lfi
from doc import generate_report

DEBUG = False

VULN_DETECTORS_TO_DEBUG = {
    "BAC": True,
    "CI": True,
    "LFI": True,
    "SQLI": True,
    "XSS": True
}

def check_detector_to_debug(vuln_dectector):
    return VULN_DETECTORS_TO_DEBUG[vuln_dectector.__name__]


def input_target_url() -> str:
    url: str = input("Enter Target URL: ")
    return url

def input_login_url() -> str:
    while True:
        login: str = input("Login is required? (y/n): ")

        if login == 'y':
            url = input("Enter Login URL: ")
            return url
        elif login == 'n':
            return ''
        else:
            print('Please enter y/n.')

def function_start(name: str) -> None:  # 함수명을 출력해주는 함수
    print('\n')
    print("#" * 100)
    print(" " * 40 + name + " " * 40)
    print("#" * 100)

def change_security(cookies, security):  # 쿠키 수정을 통해 DVWA security 단계 조절
    cookies['security'] = security

    return cookies

def dvwa(base_url, urls) -> list[str]:
    tmp_list: list[str] = []
    results: list[str] = []
    base_pattern = base_url + r"/vulnerabilities/"

    for url in urls:
        if url.endswith("/#"):
            tmp = url[:-1]  # 끝의 "/#" 부분을 제거
            tmp_list.append(tmp)
        else:
            tmp_list.append(url)

    tmp_list = list(set(tmp_list))

    for url in tmp_list:
        if re.match(base_pattern, url):
            results.append(url)

    results.sort()

    return results

def print_urls(urls):
    for url in urls:
        print(url)
    print()

def print_result(results):
    for result in results:
        print(f'\n{json.dumps(result, indent=4)}')
    print()

def make_result_file(testing_result):
    output_file = "./test/example/dvwa/Testing_Result.json"

    # JSON 파일로 데이터 저장
    with open(output_file, 'w') as json_file:
        json.dump(testing_result, json_file)

def show_report():
    file_path = '../test/example/dvwa/web_scan_report.html'

    # HTML 파일의 절대 경로를 얻기 위해 현재 작업 디렉터리를 사용합니다
    current_dir = os.path.dirname(os.path.abspath(__file__))
    absolute_path = os.path.join(current_dir, file_path)

    # 웹 브라우저로 HTML 파일 열기
    webbrowser.open('file://' + absolute_path)


# [1] Broken Access Control
def BAC(base_url, urls, testing_result, driver, login_url="", id="", pw=""):

    broken_access_control_pages = broken_access_control.get_result_urls(base_url + '/', urls)
    bac_result = []

    for page in broken_access_control_pages:
        result = {"Vulnerability": "Broken Access Control", "URL": page, "Method": '', "Payload": ''}
        bac_result.append(result)
        testing_result.append(result)

    print_result(bac_result)

    # 로그인
    if login_url != '':
        crawler.login(driver, login_url, id, pw)

    time.sleep(2)
    print()


# [2] Command Injection
def CI(driver, urls, cookies, testing_result):
    function_start("Command Injection")

    with tqdm(total=len(urls), ncols=100, desc="Command Injection", mininterval=0.1) as pbar:
        ci_result = []

        for url in urls:
            pbar.update(1)
            if not command_injection.check_attackable(driver, url):
                continue

            # form tag 수집
            driver.get(url)
            forms = crawler.get_forms(url, cookies)

            for form in forms:
                form_details = crawler.get_form_details(form)
                payloads = command_injection.generate_payload(50)

                for payload in payloads:
                    result = command_injection.submit_form(driver, form_details, url, payload)

                    if result["Vulnerability"] != "":
                        ci_result.append(result)
                        testing_result.append(result)
                        break

        print_result(ci_result)

    time.sleep(2)
    print()


# [3] Local File Inclusion
def LFI(urls, driver, testing_result):
    function_start("Local File Inclusion")

    target_urls = lfi.find_target_url(urls)
    target_file = 'etc/passwd'

    target_path = lfi.get_target_path(target_file)
    payloads = lfi.generate_payload(urls, target_file, 50)

    with tqdm(total=len(target_urls), ncols=100, desc="Local File Inclusion", mininterval=0.1) as pbar:
        lfi_result = []

        for url in target_urls:
            pbar.update(1)
            for payload in payloads:
                result = lfi.detect_lfi(driver, url, payload)

                if result["Vulnerability"] != "":
                    lfi_result.append(result)
                    testing_result.append(result)
                    break

        print_result(lfi_result)

    time.sleep(2)
    print()


# [4] SQL Injection
def SQLI(urls, driver, cookies, testing_result):
    function_start("SQL Injection")

    with tqdm(total=len(urls), ncols=100, desc="SQL Injection", mininterval=0.1) as pbar:
        si_result = []

        for url in urls:
            pbar.update(1)
            if not sql_injection.check_attackable(driver, url):
                continue

            driver.get(url)
            forms = crawler.get_forms(url, cookies)

            for form in forms:
                form_details = crawler.get_form_details(form)
                payloads = sql_injection.generate_payload(70)

                for payload in payloads:
                    result = sql_injection.submit_form(driver, form_details, url, payload)

                    if result["Vulnerability"] != "":
                        si_result.append(result)
                        testing_result.append(result)
                        break

        print_result(si_result)

    time.sleep(2)
    print()


# [5] Cross Site Scripting
def XSS(urls, driver, cookies, testing_result):
    function_start('Cross Site Scripting')

    with tqdm(total=len(urls), ncols=100, desc="Cross Site Scripting", mininterval=0.1) as pbar:
        xss_result = []

        for url in urls:
            pbar.update(1)

            if not xss.check_attackable(driver, url):
                continue

            driver.get(url)
            forms = crawler.get_forms(url, cookies)

            for form in forms:
                form_details = xss.get_form_details(form)
                payloads = xss.generate_payload(70)

                for payload in payloads:
                    result = xss.submit_form(driver, form_details, url, payload)

                    if result["Vulnerability"] != "":
                        xss_result.append(result)
                        testing_result.append(result)
                        break

        print_result(xss_result)


def main():
    start_time = time.time()

    testing_result = []
    driver = crawler.load_driver()
    driver.implicitly_wait(3)

    # 타겟 URL 입력 받기
    base_url: str = "http://localhost" if DEBUG else input_target_url()

    # 로그인 URL 입력 받기
    login_url: str = "http://localhost/login.php" if DEBUG else input_login_url()

    if login_url != '':
        # 로그인 정보 입력 받기
        id: str = "admin" if DEBUG else input("Enter ID: ")
        pw: str = "password" if DEBUG else input("Enter PW: ")

    # 로그인
    if login_url != '':
        crawler.login(driver, login_url, id, pw)

    # 쿠키 가져오기
    c = driver.get_cookies()
    cookies = crawler.get_cookie(c)
    if DEBUG: cookies = change_security(cookies, 'high')

    print(f'\nCookie: {cookies}\n')

    # 쿠기 설정
    for key, value in cookies.items():
        driver.add_cookie({"name": key, "value": value})

    # urls = open("./result_urls.txt").read().splitlines()

    # [0] 타겟 페이지 크롤링
    function_start('crawl')
    urls = crawler.crawl(base_url, base_url, driver)

    if DEBUG: urls = dvwa(base_url, urls)  # 공격 타겟을 제한
    print_urls(urls)

    ARGS = {
        "BAC": (base_url, urls, testing_result, driver, login_url, id, pw) if login_url
                    else (base_url, urls, testing_result, driver),
        "CI": (driver, urls, cookies, testing_result),
        "LFI": (urls, driver, testing_result),
        "SQLI": (urls, driver, cookies, testing_result),
        "XSS": (urls, driver, cookies, testing_result)
    }

    detectors = [BAC, CI, LFI, SQLI, XSS]
    detectors = filter(check_detector_to_debug, detectors) if DEBUG else detectors

    for func in detectors:
        func(*ARGS[func.__name__])

    make_result_file(testing_result)
    result_json = generate_report.load_json()
    generate_report.generate_report(result_json)
    show_report()

    end_time = time.time()

    broken_access_control.print_execution_time(start_time, end_time)

    driver.quit()

if __name__ == "__main__":
    main()
