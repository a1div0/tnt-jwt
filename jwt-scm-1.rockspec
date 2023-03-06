package = 'jwt'
version = 'scm-1'
source  = {
    url    = 'git@github.com:a1div0/tnt-jwt.git',
    branch = 'master',
}
description = {
    summary  = 'Module to work with JWT-token for Tarantool',
    homepage = 'https://github.com/a1div0/tnt-jwt',
    license  = 'MIT',
}
dependencies = {
    'lua >= 5.1',
}
build = {
    type = 'builtin',
    modules = {
        ['jwt'] = 'jwt/init.lua',
        ['jwt.rsa'] = 'jwt/rsa.lua',
    },
}
