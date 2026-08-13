.PHONY: all dev clean build-frontend build-app agent agent-all release

all: build-frontend build-app release

dev:
	wails3 dev

build-frontend:
	cd frontend && npm install && npm run build

build-app:
	CGO_ENABLED=1 go build -o bin/wisp .

agent:
	cd agent && CGO_ENABLED=0 go build -o ../bin/agent .

agent-all:
	cd agent && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/agent_windows_amd64.exe .
	cd agent && GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o ../bin/agent_windows_arm64.exe .
	cd agent && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/agent_linux_amd64 .
	cd agent && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../bin/agent_linux_arm64 .
	cd agent && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/agent_darwin_amd64 .
	cd agent && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o ../bin/agent_darwin_arm64 .

# release stages the operator resources (loaders/native/scripts/payloads/reports)
# next to the server binary in bin/.
release:
	mkdir -p bin/scripts bin/payloads bin/reports
	cp -r loaders bin/loaders
	cp -r native bin/native

clean:
	rm -rf bin/ frontend/dist/
