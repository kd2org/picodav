all: clean index.php
KD2FW_URL := https://fossil.kd2.org/kd2fw/doc/trunk/src/lib/KD2/

deps:
	@-mkdir -p lib/KD2/WebDAV
	wget -O lib/KD2/WebDAV/Server.php '${KD2FW_URL}WebDAV/Server.php'
	wget -O lib/KD2/WebDAV/AbstractStorage.php '${KD2FW_URL}WebDAV/AbstractStorage.php'
	wget -O webdav.js https://raw.githubusercontent.com/kd2org/webdav-manager.js/main/webdav.js
	wget -O webdav.css https://raw.githubusercontent.com/kd2org/webdav-manager.js/main/webdav.css

clean:
	rm -f index.php

index.php:
	php make.php