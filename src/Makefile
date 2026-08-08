.PHONY: all dev clean build-frontend build-app agent

all: build-frontend build-app

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

clean:
	rm -rf bin/ frontend/dist/
