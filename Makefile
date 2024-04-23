SOURCE_FILES := $(shell find . -type f -name '*.rego')
# It's necessary to call cut because kwctl command does not handle version
# starting with v.
VERSION ?= $(shell git describe | cut -c2-)

policy.wasm: $(SOURCE_FILES)
	for policy in $$(ls policies); do grep package policies/$$policy | grep -v lib | awk '{print $$2}' | xargs -I {} opa build -t wasm -e {} -o {}.tar.gz policies/$$policy; done
	for bundle in $$(ls *.gz); do policy=$$(echo $$bundle | cut -d. -f1); echo $$policy; tar xvf $$policy.tar.gz /policy.wasm ; mv policy.wasm $$policy.wasm; done
	rm *.tar.gz
	touch *.wasm # opa creates the bundle with unix epoch timestamp, fix it
