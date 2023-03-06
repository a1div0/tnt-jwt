<a href="http://tarantool.org">
   <img src="https://avatars2.githubusercontent.com/u/2344919?v=2&s=250"
align="right">
</a>

# JWT for Tarantool
## Table of contents
* [Description](#description)
* [Status](#status)
* [Installation](#installation)
* [Support algs](#support-algs)
* [API](#api)
* [Examples](#examples)
* [See also](#see-also)

## Description
This is a module to work with JWT-token for Tarantool.

Module have external dependencies:
* OpenSSL, version only 1.0.2 or 1.1. Other versions are not guaranteed to work.

## Status
Не рекомендуется к использованию из-за применения FFI. Реализовано для одного конкретного проекта.
TODO:
- без ffi
- быть в списке jwt.io
- complaens test jwt.io, прочитать спеку JWT (проблема 19-го года)
- API должно быть такое же как и у остальных библиотек
- документация должна быть
- CI, и т. д.

## Installation
You can:
* use `rock`:
``` shell
git clone https://github.com/a1div0/tnt-jwt
export DOWNLOAD_TOKEN = <DOWNLOAD_TOKEN>
make pack
```
* install the jwt module using `tarantoolctl`:
```shell
tarantoolctl rocks install https://github.com/a1div0/tnt-jwt/blob/master/jwt-1.0.0-1.rockspec
```

## Support algs
* HS256
* HS348
* HS512
* RS256
* RS348
* RS512

## API
* `local token, err = encode(data, key, alg)` - Создаёт JWT-токен на основе входных данных.
  Параметры:
    - `data` (table) - Полезная нагрузка (данные) в виде таблицы. Например имя пользователя и перечень его прав.
    - `key` (string) - Ключ, используемый для подписи данного токена. В случае использования ассиметричных
      алгоритмов шифрования, в качестве ключа следует использовать приватный ключ в формате PEM (PKCS8)
    - `alg` (string) - Необязательный. Алгоритм формирования подписи, по умолчанию = HS256
* `local body, err = decode(token, key)` - Декодирует JWT-токен и проверяет подпись.
  Параметры:
    - `token` (string) - JWT-токен
    - `key` (string | function) - Ключ, используемый для подписи данного токена (JSON Web Key). В случае
      использования ассиметричных алгоритмов шифрования, в качестве ключа следует использовать публичный ключ в
      формате PEM (PKCS8). В этот параметр можно передать функцию , которая вернёт ключ. Функция тогда должна
      содержать один аргумент - в него библиотека передаст декодированные данные токена. Пример реализации:
    ```lua
    local function get_key(token_items)
        if token_items.header.alg == 'RS256' then
            return '-----BEGIN PUBLIC KEY-----\n' .. key .. '\n-----END PUBLIC KEY-----'
        end
        return key
    end
    ```

## Examples
```lua
local jwt = require('jwt')

jwt.auto_load() -- подключаемся к so-библиотеке

local test_data = {
    payload = 'Unsigned brown fox jumps',
    more_payload = 'over the lazy dog',
    payload_num = 100500
}
local test_key = 'Salty secret salt'

local token, err = jwt.encode(test_data, test_key, 'HS256')
local body, err = jwt.decode(token, test_key)
```

## See also
* [JWT libraries](https://jwt.io/libraries)
