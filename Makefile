PACKAGE_PATH="github.com/fuserobotics/quic-channel"

gengo:
	protowrap -I $${GOPATH}/src \
		--go_out=plugins=grpc:$${GOPATH}/src \
		--proto_path $${GOPATH}/src \
		--print_structure \
		--only_specified_files \
		$$(pwd)/**/*.proto
	go install ./...

deps:
	go get -u github.com/square/goprotowrap/cmd/protowrap
