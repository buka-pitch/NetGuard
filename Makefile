.PHONY: all build clean run install

APP = netmon
BINDIR = bin

all: build

build:
	@mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build -o $(BINDIR)/$(APP) .

run: build
	sudo ./$(BINDIR)/$(APP) -config $$HOME/.config/netmon/config.json

clean:
	rm -rf $(BINDIR)
	rm -f *.db

install: build
	install -d /usr/local/bin
	install -m 755 $(BINDIR)/$(APP) /usr/local/bin/$(APP)
	install -d /etc/netmon
	install -m 644 scripts/netmon.service /etc/systemd/system/
	install -d /var/lib/netmon
	systemctl daemon-reload

test:
	go test ./...
