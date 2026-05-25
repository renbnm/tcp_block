#include "tcp.h"
#include <cstdio>

Tcp::Tcp(const std::string r) {
	unsigned int port;
	int res = sscanf(r.c_str(), "%u", &port);
	if (res != 1 || port > 65535) {
		fprintf(stderr, "Tcp::Tcp sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
	port_ = static_cast<uint16_t>(port);
}

Tcp::operator std::string() const {
	char buf[32]; // enough size
	sprintf(buf, "%u", port_);
	return std::string(buf);
}