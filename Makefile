SHELL := /bin/bash

DOWNLOAD_ENDPOINT = download.tarantool.io
DOWNLOAD_USER = tarantool
TARANTOOL_LINUX_BUNDLE_NAME = enterprise/release/linux/x86_64/2.10/tarantool-enterprise-sdk-nogc64-2.10.4-0-r523.linux.x86_64.tar.gz
TARANTOOL_MAC_BUNDLE_NAME = enterprise/release/macos/x86_64/2.10/tarantool-enterprise-sdk-gc64-2.10.4-0-r523.macos.x86_64.tar.gz


sdk:
	curl -o ./sdk.tar.gz -L https://${DOWNLOAD_USER}:${DOWNLOAD_TOKEN}@${DOWNLOAD_ENDPOINT}/${TARANTOOL_LINUX_BUNDLE_NAME}
	mkdir -p ./sdk && tar -xzvf ./sdk.tar.gz -C ./sdk --strip 1
	rm -f ./sdk.tar.gz

.rocks: sdk
	source ./sdk/env.sh \
	&& tarantoolctl rocks install luacheck --only-server=./sdk/rocks \
	&& tarantoolctl rocks install luatest 0.5.7 --only-server=./sdk/rocks \
	&& tarantoolctl rocks install luacov 0.13.0 --only-server=./sdk/rocks \
	&& tarantoolctl rocks install luacov-reporters 0.1.0 --only-server=./sdk/rocks \
	&& tarantoolctl rocks make jwt-scm-1.rockspec --only-server=./sdk/rocks

pack: .rocks
	source ./sdk/env.sh && \
	tarantoolctl rocks make jwt-1.0.0-1.rockspec && \
	tarantoolctl rocks pack jwt

pack.scm:
	source ./sdk/env.sh && \
	tarantoolctl rocks make jwt-scm-1.rockspec && \
	tarantoolctl rocks pack jwt

clean:
	rm -rf .rocks sdk *.out

test: test.lint test.unit ## Запуск всех тестов

test.lint: ## Запуск luacheck
	source ${PWD}/sdk/env.sh \
	&& .rocks/bin/luacheck jwt/ test/ --max-line-length 200

test.unit: ## Запуск unit тестов
	source ${PWD}/sdk/env.sh && \
	.rocks/bin/luatest -c --coverage && \
	.rocks/bin/luacov -r summary && cat luacov.report.out

test.docker:
	set -ex
	docker build -f test-libssl1.0.Dockerfile -t tnt-jwt-test .
	docker run -dit -v ${PWD}:/data --name=tnt-jwt-testbox tnt-jwt-test \
		bash -c "cd /data/ && rm -rf .rocks && make .rocks && chmod -R 777 .rocks && make test"
	docker wait tnt-jwt-testbox
	docker logs tnt-jwt-testbox
	docker rm tnt-jwt-testbox
