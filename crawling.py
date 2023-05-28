import time
from http import HTTPStatus

import requests
from urllib.parse import urljoin, urlencode, urlsplit, urlparse
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.common import NoSuchElementException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

import xss
import sql_injection

base_url: str = 'http://localhost'
login_url: str = f'{base_url}/login.php'
target_url: str = f'{base_url}/vulnerabilities/xss_r/'
visited_urls = set()


def get_cookie(cookies) -> dict:  # 주어진 데이터중 필요한 부분을 뽑아서 쿠키를 만들어 반환
    return {cookie.get('name'): cookie.get('value') for cookie in cookies}


def load_driver():  # driver 반환 함수
    """
    크롬 드라이버 객체 반환 및 필요에 따라 디버깅 옵션 설정
    """

    options = Options()
    # Options for debugging
    options.add_argument("--allow-running-insecure-content")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("window-size = 1920, 1080")
    options.add_argument("lang=ko_KR")

    service = Service("drivers/chromedriver")

    return webdriver.Chrome(service=service, options=options)


def login(driver):  # login 함수
    driver.get(login_url)

    elem = driver.find_element(By.NAME, "username")
    elem.send_keys("admin")

    elem = driver.find_element(By.NAME, "password")
    elem.send_keys("password")

    elem = driver.find_element(By.NAME, "Login")
    elem.click()


def crawl(url):  # 쿠키 매개변수가 있는 수정된 crawl() 함수
    # URL 방문
    driver.get(url)

    page_urls = []  # 현재 페이지의 URL을 저장하는 리스트

    # 현재 페이지에서 링크된 URL 수집
    links = driver.find_elements(By.CSS_SELECTOR, "a")
    for link in links:
        href = link.get_attribute("href")
        if href and href.startswith(base_url) and href not in visited_urls:
            if href != f"{base_url}/logout.php":
                visited_urls.add(href)
                page_urls.append(href)

    for page_url in page_urls:
        sub_page_urls = crawl(page_url)
        page_urls.extend(sub_page_urls)

    # 현재 페이지 처리 후에 뒤로 가기
    driver.back()

    return page_urls


def get_forms(url, cookies):  # 모든 form 태그 반환
    """
    BeautifulSoup로 form 태그를 모두 반환
    """

    page_content = requests.get(url, cookies=cookies).content
    soup = BeautifulSoup(page_content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):  # form tag 내의 세부 데이터 추출 함수
    details = {}

    # form의 이동할 action url
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()

    inputs = []

    for tag in form.find_all(["input", "textarea", "select", "checkbox", "button"]):
        tag_type = tag.name
        tag_name = tag.attrs.get("name")
        inputs.append({"type": tag_type, "name": tag_name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details


def get_xss_payload() -> list[str]:
    return xss.xss()


def get_sql_injection_payload() -> list[str]:
    return sql_injection.sql_injection()


if __name__ == "__main__":
    driver = load_driver()

    # 로그인
    login(driver)

    # 쿠키 가져오기
    c = driver.get_cookies()
    cookies = get_cookie(c)

    print(f'Cookie: {cookies}')

    # 쿠기 설정
    for key, value in cookies.items():
        driver.add_cookie({"name": key, "value": value})

    # 타겟 페이지 크롤링
    urls = crawl(base_url)

    for url in urls:
        # form tag 수집
        driver.get(url)
        forms = get_forms(url, cookies)

        for form in forms:
            form_details = get_form_details(form)
            xss_payloads = get_xss_payload()



