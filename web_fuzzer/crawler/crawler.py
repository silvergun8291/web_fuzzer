import re
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common import TimeoutException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


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


def login(driver, login_url, id, pw):  # login 함수
    driver.get(login_url)

    elem = driver.find_element(By.NAME, "username")
    elem.send_keys(id)

    elem = driver.find_element(By.NAME, "password")
    elem.send_keys(pw)

    elem = driver.find_element(By.NAME, "Login")
    elem.click()


def crawl(base_url, url, driver, depth=0):  # 쿠키 매개변수가 있는 수정된 crawl() 함수
    # URL 방문
    driver.get(url)

    depth += 1

    page_urls = []  # 현재 페이지의 URL을 저장하는 리스트

    # 현재 페이지에서 링크된 URL 수집
    links = driver.find_elements(By.CSS_SELECTOR, "a")
    for link in links:
        href = link.get_attribute("href")
        if href and href.startswith(base_url) and href not in visited_urls:
            pattern = r"phpids"

            if href != f"{base_url}/logout.php" and not (re.search(pattern, href)):
                visited_urls.add(href)
                page_urls.append(href)

            # onclick 이벤트 처리 (팝업 창 클릭)
            onclick_attr = link.get_attribute("onclick")
            if onclick_attr and "popUp" in onclick_attr:
                driver.execute_script(onclick_attr)

                # 팝업 창 대기 및 처리
                try:
                    WebDriverWait(driver, 3).until(EC.number_of_windows_to_be(3))
                    window_handles = driver.window_handles
                    driver.switch_to.window(window_handles[2])

                    # 팝업 창의 URL 수집
                    popup_url = driver.current_url
                    page_urls.append(popup_url)

                    driver.close()
                    driver.switch_to.window(window_handles[1])
                except TimeoutException:
                    print("Time Out!")
    if depth <= 0:
        for page_url in page_urls:
            sub_page_urls = crawl(base_url, page_url, driver)
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


def get_form_details(form) -> dict:
    # form에서 세부 내용을 뽑아내는 함수

    details = {}

    # form의 이동할 action url
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()

    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details



