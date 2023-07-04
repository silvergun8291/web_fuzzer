from time import time
import asyncio
import aiohttp
import re
import requests
from tqdm import tqdm
import os

directory_list_path: str = 'static/dictionary/url.dictionary.txt'

def print_execution_time(start_time, end_time):  # 실행 시간 출력 함수
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    print(f"\nExecution time: {int(minutes)} minutes {int(seconds)} seconds")


def function_start(name: str) -> None:  # 함수명을 출력해주는 함수
    print('\n')
    print("#" * 100)
    print(" " * 40 + name + " " * 40)
    print("#" * 100)


def make_num_list(max: int) -> list[int]:  # 1 ~ (max-1) 범위의 num_list를 만드는 함수
    num_list: list[int] = []

    for i in range(1, max):
        num_list.append(i)

    return num_list


def deduplicate(urls: list[str], target_urls: list[str]) -> list[str]:  # 중복 제거 함수
    # 크롤링한 URL에 없는 URL만 골라서 리턴
    result: list[str] = []

    for url in urls:
        if url not in target_urls:
            result.append(url)

    return result


def print_result(urls):
    for url in urls:
        print(url)


def print_testing_result(sensitive_pages: list[str], deprecated_pages: list[str]) -> None:  # 테스팅 결과를 출력하는 함수
    print('\nSensitive Pages')

    for url in sensitive_pages:
        print(url)

    print()


    print('\nDeprecated Pages')

    for url in deprecated_pages:
        print(url)

    print()


# 비동기 방식으로 find_directory() 함수를 호출하여 해당 페이지가 존재하는지 확인하는 함수
async def async_func(target_domain: str, directory_list: list[str], results: list) -> None:
    conn = aiohttp.TCPConnector(limit_per_host=10)
    async with aiohttp.ClientSession(connector=conn) as s:
        futures = [
            asyncio.create_task(find_directory(s, f"{target_domain}{directory}", results))
            for directory in directory_list
        ]

        # 프로그래스바
        with tqdm(total=len(futures), desc="Broken Access Control", unit="directory", ncols=100) as pbar:
            for future in asyncio.as_completed(futures):
                result = await future
                pbar.update(1)


# 비동기 방식으로 해당 URL에 GET 요청을 보낸 후 상태 코드를 통해 페이지 존재 유무를 확인하는 함수
async def find_directory(s: aiohttp.ClientSession, sub_directory_path: str, results: list) -> list[str]:
    try:
        async with s.get(sub_directory_path) as r:
            if r.status == 200:
                output = sub_directory_path
                results.append(output)

                return output
            elif r.status == 404:
                pass
            else:
                raise Exception("status_code", r.status)
    except aiohttp.client_exceptions.ClientConnectionError as e:
        # Get Address info failed Error...
        pass
    except Exception as e:
        status_code, error_status = e.args
        output = (sub_directory_path, error_status)

        return output


def traversal_num(urls: list[str], results: list) -> None:
    # https://dreamhack.io/lecture/roadmaps/1
    # URL 마지막 숫자 값으로 페이지가 결정되는 경우 숫자 값을 조작하여 웹 페이지 탐색
    function_start('traversal_num')

    targets: list[str] = []
    longest_end_part_length: int = 0

    # 숫자 값을 통해 페이지를 조작할 수 있는 URL 추출
    for url in urls:
        # URL에서 마지막 부분 추출
        end_part = url.split("/")[-1]

        # 추출한 부분이 숫자인지 확인
        if end_part.isdigit():
            targets.append(url[:-len(end_part)])

            # 가장 긴 숫자 값의 길이를 구함
            if len(end_part) > longest_end_part_length:
                longest_end_part_length = len(end_part)

    # targets url에서 중복 제거
    targets = list(set(targets))

    # targets이 없으면 함수 종료
    if (targets == []):
        return None

    # 위에서 구한 숫자 길이 만큼 1 뒤에 0을 붙임
    size: str = '1'
    for _ in range(longest_end_part_length):
        size += '0'

    # 위에서 구한 사이즈 크기의 숫자 리스트를 만듦
    num_list = make_num_list(int(size))

    # 추출한 URL을 조작하여 레거시 페이지 탐색
    for url in targets:
        asyncio.run(async_func(url, num_list, results))


def traversal_id(urls: list[str], results: list) -> None:
    # https://www.jnu.ac.kr/WebApp/web/HOM/COM/Board/board.aspx?boardID=12
    # id 값으로 페이지가 결정될 때 id 값을 조작하여 웹 페이지 탐색
    function_start('traversal_id')

    targets: list[str] = []
    longest_id_length: int = 0

    for url in urls:
        # 정규식 패턴을 사용하여 URL에서 "id" 계열 단어 추출
        pattern = r"\b(\w*id)\b"
        matches = re.findall(pattern, url, re.IGNORECASE)

        if len(matches) > 0:
            base_url = url[:url.find(matches[0])]
            targets.append(f'{base_url}{matches[-1]}=')

            # 길이가 가장 긴 id의 길이를 구함
            start = url.find(matches[-1]) + len(matches[-1]) + 1
            if len(url[start:]) > longest_id_length:
                longest_id_length = len(url[start:])

    # targets url에서 중복 제거
    targets = list(set(targets))

    # targets이 없으면 함수 종료
    if (targets == []):
        return None

    # 위에서 구한 숫자 길이 만큼 1 뒤에 0을 붙임
    size: str = '1'
    for _ in range(longest_id_length):
        size += '0'

    # 위에서 구한 size 크기의 숫자 리스트를 만듦
    num_list = make_num_list(int(size))

    # 추출한 URL을 조작하여 레거시 페이지 탐색
    for url in targets:
        asyncio.run(async_func(url, num_list, results))


def get_result_urls(target_domain: str, urls: list[str]) -> list[list[str], list[str]]:
    start_time = time()

    function_start('Broken Access Control')

    result_pages: list[str] = []  # Broken Access Control 취약점이 있는 페이지

    # [1] 접근하면 안되는 경로에 접근 가능한지 확인
    directory_list: list[str] = open(directory_list_path).read().splitlines()

    for i in range(len(directory_list)):    # 딕셔너리 파일 처리
        directory_list[i] = directory_list[i].replace('/', '')

    result1: list[str] = []
    asyncio.run(async_func(target_domain, directory_list, result1))

    result1 = list(set(result1))
    result_pages.extend(result1)

    # [2] 페이지 번호를 가지고 경로 순회
    result2: list[str] = []
    traversal_num(urls, result2)

    result_pages.extend(deduplicate(result2, urls))

    # [3] ID 값을 가지고 경로 순회
    result3: list[str] = []
    traversal_id(urls, result3)

    # 새롭게 찾은 페이지 중 크롤링한 결과에 없고 기존에 deprecated_pages에 없던 페이지만 deprecated_pages에 추가
    tmp = deduplicate(result3, urls)
    result_pages.extend(deduplicate(tmp, result_pages))

    if 'http://localhost/' in result_pages:
        result_pages.remove('http://localhost/')

    end_time = time()
    print_execution_time(start_time, end_time)

    return result_pages



def traversal_num_test():
    urls = ['https://wikidocs.net/17', 'https://wikidocs.net/9']

    result = []
    traversal_num(urls, result)

    print(result)


def traversal_id_test():
    urls = ['https://www.jnu.ac.kr/WebApp/web/HOM/COM/Board/board.aspx?boardID=11',
            'https://www.jnu.ac.kr/WebApp/web/HOM/COM/Board/board.aspx?boardID=5']

    traversal_id(urls)


def broken_access_control_test():
    urls = [
        'https://wikidocs.net/17',
        'https://wikidocs.net/9',
        'https://www.jnu.ac.kr/WebApp/web/HOM/COM/Board/board.aspx?boardID=11',
        'https://www.jnu.ac.kr/WebApp/web/HOM/COM/Board/board.aspx?boardID=5'
    ]
    target_domain: str = 'http://localhost/'
    directory_list_path = './PHP.fuzz.txt'

    start_time = time()

    function_start('path_traversal')

    deprecated_pages: list[str] = []  # 유지 보수가 중단된 페이지를 찾음
    sensitive_pages: list[str] = []  # 접근하면 안되는 페이지를 찾음

    # [1] 접근하면 안되는 경로에 접근 가능한지 확인
    directory_list: list[str] = open(directory_list_path).read().splitlines()
    result1: list[str] = []
    asyncio.run(async_func(target_domain, directory_list, result1))
    print_result(result1)

    sensitive_pages.extend(result1)

    # [2] 페이지 번호를 가지고 경로 순회
    result2: list[str] = []
    traversal_num(urls, result2)
    print_result(result2)

    deprecated_pages.extend(deduplicate(result2, urls))

    # [3] ID 값을 가지고 경로 순회
    result3: list[str] = []
    traversal_id(urls, result3)
    print_result(result3)

    # 새롭게 찾은 페이지 중 크롤링한 결과에 없고 기존에 deprecated_pages에 없던 페이지만 deprecated_pages에 추가
    tmp = deduplicate(result3, urls)
    deprecated_pages.extend(deduplicate(tmp, deprecated_pages))

    print_testing_result(deprecated_pages, sensitive_pages)

    end_time = time()
    print_execution_time(start_time, end_time)

    return (sensitive_pages, deprecated_pages)
