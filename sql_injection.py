from fuzzingbook.WebFuzzer import *


def sql_injection() -> list[str]:
    SQL_Injection_Grammar: Grammar = {
        '<start>': ['<sql>'],
        '<sql>': [],
    }

    result: list[str] = []

    return result
