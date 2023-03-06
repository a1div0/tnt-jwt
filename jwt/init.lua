-- luacheck: ignore 421

local crypto = require("crypto")
local digest = require("digest")
local json = require("json")
local rsa = require("jwt.rsa")

local jwt = {}

local function rsasha_sign(data, private_pem, hash_alg)
    local rsa_inst, err = rsa:new{
        private_key =  private_pem,
        algorithm = hash_alg,
    }
    if err ~= nil then
        return nil, err
    end

    local ver_res, ver_err = rsa_inst:sign(data)
    if ver_err ~= nil then
        return nil, ver_err
    end

    return ver_res
end

local function rsasha_verify(data, signature, public_pem, hash_alg)
    local rsa_inst, err = rsa:new{
        public_key =  public_pem,
        algorithm = hash_alg,
    }
    if err ~= nil then
        return nil, err
    end

    local ver_res, ver_err = rsa_inst:verify(data, signature)
    if ver_err ~= nil then
        return nil, ver_err
    end

    return ver_res
end


local alg_sign = {
    HS256 = function(data, key)
        return crypto.hmac.sha256(key, data)
    end,
    HS384 = function(data, key)
        return crypto.hmac.sha384(key, data)
    end,
    HS512 = function(data, key)
        return crypto.hmac.sha512(key, data)
    end,
    RS256 = function(data, key)
        return rsasha_sign(data, key, "sha256")
    end,
    RS384 = function(data, key)
        return rsasha_sign(data, key, "sha384")
    end,
    RS512 = function(data, key)
        return rsasha_sign(data, key, "sha512")
    end,
}

local alg_verify = {
    HS256 = function(data, signature, key)
        return signature == alg_sign.HS256(data, key)
    end,
    HS384 = function(data, signature, key)
        return signature == alg_sign.HS384(data, key)
    end,
    HS512 = function(data, signature, key)
        return signature == alg_sign.HS512(data, key)
    end,
    RS256 = function(data, signature, key)
        return rsasha_verify(data, signature, key, "sha256")
    end,
    RS384 = function(data, signature, key)
        return rsasha_verify(data, signature, key, "sha384")
    end,
    RS512 = function(data, signature, key)
        return rsasha_verify(data, signature, key, "sha512")
    end,
}

local function decode_token_items(header_b64, body_b64, sig_b64)

    local header_str = digest.base64_decode(header_b64)
    local body_str = digest.base64_decode(body_b64)
    local sig_str = digest.base64_decode(sig_b64)

    local header = json.decode(header_str)
    local body = json.decode(body_str)

    return {
        header = header,
        body = body,
        signature = sig_str,
    }
end

---@comment Ищет и подключает модуль библиотеки OpenSSL
---@return nil
function jwt.auto_load()
    local handle = io.popen("find /usr/ | grep libssl.so")
    local result = handle:read("*a")
    handle:close()

    local lines = result:split("\n")
    for _, filename in pairs(lines) do
        if filename:endswith("/libssl.so.1.1") or filename:endswith("/libssl.so.10") then --libssl.so.1.0.2k
            jwt.libssl_load(filename)
            return
        end
    end

    error("Could not find libssl")
end

---@comment Подключить конкретный модуль библиотеки OpenSSL
---@param libssl_filename string Полный путь к файлу libssl.so
---@return nil
function jwt.libssl_load(libssl_filename)
    if type(libssl_filename) ~= "string" then
        return nil, "Argument #1 must be string"
    end

    rsa.libssl_load(libssl_filename)
end


---@comment Создаёт JWT-токен на основе входных данных.
---@comment В случае использования ассиметричных алгоритмов шифрования, в качестве ключа следует использовать
---@comment приватный ключ в формате PEM (PKCS8)
---@param data table Полезная нагрузка (данные) в виде таблицы. Например имя пользователя и перечень его прав.
---@param key string Ключ, используемый для подписи данного токена
---@param alg string Необязательный. Алгоритм формирования подписи, по умолчанию = HS256
---@return string JWT-токен
function jwt.encode(data, key, alg)

    if type(data) ~= "table" then
        return nil, "Argument #1 must be table"
    end

    if type(key) ~= "string" then
        return nil, "Argument #2 must be string"
    end

    alg = alg or "HS256"
    local hash_function = alg_sign[alg]
    if not hash_function then
        return nil, "Algorithm not supported"
    end

    local header = {
        typ = "JWT",
        alg = alg
    }
    local base64_encode_opt = {
        nopad = true,
        nowrap = true,
        urlsafe = true
    }

    local segments = {
        digest.base64_encode(json.encode(header), base64_encode_opt),
        digest.base64_encode(json.encode(data), base64_encode_opt)
    }

    local signing_input = table.concat(segments, ".")
    local ok, signature, err = pcall(hash_function, signing_input, key)
    if not ok or err then
        return nil, err or signature
    end

    segments[#segments + 1] = digest.base64_encode(signature, base64_encode_opt)

    return table.concat(segments, ".")
end


---@comment Декодирует JWT-токен и проверяет подпись. В случае использования ассиметричных алгоритмов
---@comment шифрования, в качестве ключа следует использовать публичный ключ в формате PEM (PKCS8)
---@param jwt_token string JWT-токен
---@param key string|function Ключ, используемый для подписи данного токена (JSON Web Key)
---@param verify bool Необязательный. Параметр для отладочной среды. Если передать false - подпись проверяться не будет. По умолчанию = true.
---@return table Верифицированное тело токена
function jwt.decode(jwt_token, key, verify)

    if type(jwt_token) ~= "string" then
        return nil, "Argument #1 must be string"
    end

    local key_is_func = type(key) == "function"
    if not key_is_func and type(key) ~= "string" then
        return nil, "Argument #2 must be string or function"
    end

    local token_items_str = jwt_token:split(".")
    if #token_items_str ~= 3 then
        return nil, "Invalid token"
    end

    local header_b64, body_b64, sig_b64 = token_items_str[1], token_items_str[2], token_items_str[3]
    local signing_input = header_b64 .. "." .. body_b64

    local ok, token_items = pcall(decode_token_items, header_b64, body_b64, sig_b64)
    if not ok then
        return nil, "Invalid json"
    end

    if not token_items.header.typ or token_items.header.typ ~= "JWT" then
        return nil, "Invalid typ"
    end

    if key_is_func then
        key = key(token_items)
    end

    if verify ~= false then
        if not token_items.header.alg or type(token_items.header.alg) ~= "string" then
            return nil, "Invalid alg"
        end

        local verify_func = alg_verify[token_items.header.alg]
        if not verify_func then
            return nil, ("Algorithm %s is not supported"):format(token_items.header.alg)
        end

        local ok, result, err = pcall(verify_func, signing_input, token_items.signature, key)
        if not ok or err then
            return nil, err or result
        end
        if not result then
            return nil, "Invalid signature"
        end
    end

    return token_items.body
end

return jwt
