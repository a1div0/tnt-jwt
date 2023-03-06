local luatest = require('luatest')
local jwt = require('jwt')
local fio = require('fio')

local group = luatest.group()

jwt.auto_load()

local test_data = {
    payload = 'Unsigned brown fox jumps',
    more_payload = 'over the lazy dog',
    payload_num = 100500
}
local test_key = 'Salty secret salt'
local token_HS256 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjoiVW5zaWduZWQgYnJvd24gZm94IGp1bXBzIiwibW9yZV9wY'
        ..'Xlsb2FkIjoib3ZlciB0aGUgbGF6eSBkb2ciLCJwYXlsb2FkX251bSI6MTAwNTAwfQ.r7fkDa86-Pud5MLXri0OF8uqEMBQAKaofPTEcZGBT8'
        ..'c'
local token_RS256 = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjoiVW5zaWduZWQgYnJvd24gZm94IGp1bXBzIiwibW9yZV9wY'
        ..'Xlsb2FkIjoib3ZlciB0aGUgbGF6eSBkb2ciLCJwYXlsb2FkX251bSI6MTAwNTAwfQ.ca1h8sHHmu1XW17vkaOThYuC5Nl2xQO60WAhj66hD9'
        ..'5JMz-Cm_86VQ2D68BcH9TtqgHSnHd9foG0ZmmRH2J5Ow01ajAeTWCp1CpHBRPtY07KIRiKBB9819FC2gqfNecKK9FEJOXbdj4bWH2xgoBDHp'
        ..'LvXFtScKlVwmBbMerU8LTE_4woa4LAJNQxOWseMLgEMGCMSaBvtsDST5VdktKwn71G1_-PnPzKzu9euXDqxfSr1SC-Ks4JVNnvvbKQBRz842'
        ..'tm9TZXBtWTHqJL-y7S4NfdOLO2vBcVZV4KjHyPCAUHu9fNVPSccayy_nPWtN6yli4-RGEXdNpDrgXpuxEljg'

local function load_file(filename)
    local file = fio.open(filename, {'O_RDONLY'})
    local data = file:read()
    file:close()

    return data
end

local test_private_pem = load_file('./test/unit/data/private.pem')
local test_public_pem = load_file('./test/unit/data/public.pem')

local function get_test_key(token_items)
    if token_items.header.alg == 'HS256' then
        return test_key
    elseif token_items.header.alg == 'RS256' then
        return test_public_pem
    end
end

group.test_encode_HS256 = function()

    local token, err = jwt.encode(test_data, test_key, 'HS256')
    luatest.assert_equals(err, nil)
    luatest.assert_equals(type(token), 'string')
    luatest.assert_equals(token, token_HS256)

end

group.test_encode_RS256 = function()

    local token, err = jwt.encode(test_data, test_private_pem, 'RS256')
    luatest.assert_equals(err, nil)
    luatest.assert_equals(type(token), 'string')
    luatest.assert_equals(token, token_RS256)

end

group.test_encode_unsupported_alg = function()

    local token, err = jwt.encode(test_data, test_private_pem, 'ABCD')
    luatest.assert_equals(token, nil)
    luatest.assert_equals(err, 'Algorithm not supported')

end

group.test_decode_HS256 = function()

    local body, err = jwt.decode(token_HS256, test_key)
    luatest.assert_equals(err, nil)
    luatest.assert_equals(body, test_data)

end

group.test_decode_RS256 = function()

    local body, err = jwt.decode(token_RS256, test_public_pem)
    luatest.assert_equals(err, nil)
    luatest.assert_equals(body, test_data)

end

group.test_decode_auto = function()

    local body, err = jwt.decode(token_HS256, get_test_key)
    luatest.assert_equals(err, nil)
    luatest.assert_equals(body, test_data)

    body, err = jwt.decode(token_RS256, get_test_key)
    luatest.assert_equals(err, nil)
    luatest.assert_equals(body, test_data)

end
