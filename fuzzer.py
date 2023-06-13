import time
import json
import re

from tqdm import tqdm

import crawler
import xss
import sql_injection
import command_injection
import broken_access_control
import lfi
import generate_report


def input_target_url() -> str:
    url: str = input("Enter Target URL: ")
    return url


def input_login_url() -> str:
    login: str = input("Login is required? (y/n): ")

    if login == 'y':
        url = input("Enter Login URL: ")
        return url
    else:
        return ''


def input_id_pw() -> list[str, str]:
    id: str = input("Enter ID: ")
    pw: str = input("Enter PW: ")

    return [id, pw]


def function_start(name: str) -> None:  # 함수명을 출력해주는 함수
    print('\n')
    print("#" * 100)
    print(" " * 40 + name + " " * 40)
    print("#" * 100)


def change_security(cookies, security):  # 쿠키 수정을 통해 DVWA security 단계 조절
    cookies['security'] = security

    return cookies


def dvwa(urls) -> list[str]:
    tmp_list: list[str] = []
    results: list[str] = []
    base_pattern = r"http://localhost/vulnerabilities/"

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


def print_list(list):
    for data in list:
        print(f'\n{data}')


def make_reuslt_file(testing_result):
    output_file = "Testing_Result.json"

    # JSON 파일로 데이터 저장
    with open(output_file, 'w') as json_file:
        json.dump(testing_result, json_file)


def fuzzing():
    start_time = time.time()

    testing_result = []
    driver = crawler.load_driver()

    # 타겟 URL 입력 받기
    base_url: str = input_target_url()

    # 로그인 URL 입력 받기
    login_url: str = input_login_url()

    # 로그인 정보 입력 받기
    id, pw = input_id_pw()

    # 로그인
    if login_url != '':
        crawler.login(driver, login_url, id, pw)

    # 쿠키 가져오기
    c = driver.get_cookies()
    cookies = crawler.get_cookie(c)
    cookies = change_security(cookies, 'high')

    print(f'\nCookie: {cookies}\n')

    # 쿠기 설정
    for key, value in cookies.items():
        driver.add_cookie({"name": key, "value": value})

    # urls = open("./result_urls.txt").read().splitlines()

    # [0] 타겟 페이지 크롤링
    function_start('crawl')
    urls = crawler.crawl(base_url, base_url, driver)
    print_list(urls)


    # [1] Broken Access Control
    broken_access_control_pages = broken_access_control.get_result_urls(base_url + '/', urls)

    for page in broken_access_control_pages:
        bac_result = {"Vulnerability": "Broken Access Control", "URL": page, "Method": '', "Payload": ''}
        testing_result.append(bac_result)

    urls = dvwa(urls)  # 공격 타겟을 제한

    # 로그인
    if login_url != '':
        crawler.login(driver, login_url, id, pw)


    # [2] Command Injection
    function_start("Command Injection")

    with tqdm(total=len(urls), ncols=100, desc="Command Injection", mininterval=0.5) as pbar:
        ci_result = []

        for url in urls:
            if not command_injection.check_attackable(driver, url):
                continue

            # form tag 수집
            driver.get(url)
            forms = crawler.get_forms(url, cookies)

            for form in forms:
                form_details = crawler.get_form_details(form)
                payloads = command_injection.generate_payload()

                for payload in payloads:
                    result = command_injection.submit_form(driver, form_details, url, payload)

                    if result["Vulnerability"] != "":
                        ci_result.append(result)
                        testing_result.append(result)
                        break

            pbar.update(1)

        pbar.update(len(urls))

        print(json.dumps(ci_result, indent=4))


    # [3] Local File Inclusion
    function_start("Local File Inclusion")

    target_urls = lfi.find_target_url(urls)
    target_file = 'etc/passwd'

    target_path = lfi.get_target_path(target_file)
    payloads = lfi.generate_payload(urls, target_file, 50)

    with tqdm(total=len(target_urls), ncols=100, desc="Local File Inclusion", mininterval=0.5) as pbar:
        lfi_result = []

        for url in target_urls:
            for payload in payloads:
                result = lfi.detect_lfi(driver, url, payload)

                if result["Vulnerability"] != "":
                    lfi_result.append(result)
                    testing_result.append(result)
                    break

            pbar.update(1)

        pbar.update(len(urls))

        print(json.dumps(lfi_result, indent=4))


    # [4] SQL Injection
    function_start("SQL Injection")

    with tqdm(total=len(urls), ncols=100, desc="SQL Injection", mininterval=0.5) as pbar:
        si_result = []

        for url in urls:
            if not sql_injection.check_attackable(driver, url):
                continue

            driver.get(url)
            forms = crawler.get_forms(url, cookies)

            for form in forms:
                form_details = crawler.get_form_details(form)
                payloads = sql_injection.generate_payload()

                for payload in payloads:
                    result = sql_injection.submit_form(driver, form_details, url, payload)

                    if result["Vulnerability"] != "":
                        si_result.append(result)
                        testing_result.append(result)
                        break

            pbar.update(1)

        pbar.update(len(urls))

        print(json.dumps(si_result, indent=4))


    # [5] Cross Site Scripting
    function_start('Cross Site Scripting')

    with tqdm(total=len(urls), ncols=100, desc="Cross Site Scripting", mininterval=0.5) as pbar:
        xss_result = []

        for url in urls:
            if not xss.check_attackable(driver, url):
                continue

            driver.get(url)
            forms = crawler.get_forms(url, cookies)

            for form in forms:
                form_details = xss.get_form_details(form)
                payloads = xss.generate_payload()

                for payload in payloads:
                    result = xss.submit_form(driver, form_details, url, payload)

                    if result["Vulnerability"] != "":
                        xss_result.append(result)
                        testing_result.append(result)
                        break

            pbar.update(1)

        pbar.update(len(urls))

        print(json.dumps(xss_result, indent=4))

    make_reuslt_file(testing_result)
    result_json = generate_report.load_json()
    generate_report.generate_report(result_json)

    end_time = time.time()

    broken_access_control.print_execution_time(start_time, end_time)

    driver.quit()


if __name__ == "__main__":
    fuzzing()
