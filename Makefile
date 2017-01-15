
all: install

install_deps:
	sudo -H pip3 install -r requirements.txt

help:
	@echo
	@echo "now call sudo systemctl daemon-reload"
	@echo ".. enable service via: sudo systemctl enable route-manager"
	@echo ".. start service via:  sudo systemctl start route-manager"
	@echo ".. status via:         sudo systemctl status route-manager"
	@echo ".. log info via:       sudo journalctl -u route-manager"

install:
	install -m 755 -T route-manager.py /usr/bin/router-manager
ifeq (,$(wildcard /etc/route-manager/conf.json))
	mkdir -p /etc/route-manager
	install -m 644 -T conf.json /etc/route-manager/conf.json
else
	  $(warning /etc/route-manager/conf.json exists - I did not overwrite this file)
endif
	install -m 644 assets/route-manager.service /lib/systemd/system/
	make help

uninstall:
	rm -rf /usr/bin/route-manager
	rm -rf /lib/systemd/system/route-manager.service


