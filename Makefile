BASE_IMAGE_TAG = latest
BUILD_IMAGE_TAG = v2

all:
	go build -ldflags='-s -w' -o adapter

STAGE_DIR = stage

copy_adpt:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	#
	cp registry-adapter/adapter ${STAGE_DIR}/usr/local/bin/

stage_init:
	rm -rf ${STAGE_DIR}; mkdir -p ${STAGE_DIR}

stage_adpt: stage_init copy_adpt

adapter_image: stage_adpt
	docker pull neuvector/adapter_base:${BASE_IMAGE_TAG}
	docker build --build-arg NV_TAG=$(NV_TAG) --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} -t neuvector/registry-adapter -f registry-adapter/build/Dockerfile .

binary:
	@echo "Making $@ ..."
	@docker pull neuvector/build_fleet:${BUILD_IMAGE_TAG}
	@docker run --rm -ia STDOUT --name build --net=none -v $(CURDIR):/go/src/github.com/neuvector/registry-adapter -w /go/src/github.com/neuvector/registry-adapter --entrypoint ./make_bin.sh neuvector/build_fleet:${BUILD_IMAGE_TAG}
