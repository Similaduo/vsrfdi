build:
	go build -v -pgo=auto -trimpath -gcflags "all=-l=4" -ldflags "-s -w -linkmode=internal -extldflags '-static --static-pie' -buildid=" -buildmode=pie -a -o vsrfdi