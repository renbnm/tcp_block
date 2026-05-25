#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <string>

struct Tcp final {
	static const int Size = 2;

	// constructor
	Tcp() {}
	Tcp(const uint16_t r) : port_(r) {}
	Tcp(const std::string r);

	// casting operator
	operator uint16_t() const { return port_; } // default
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Tcp& r) const { return port_ == r.port_; }
	bool operator != (const Tcp& r) const { return port_ != r.port_; }

protected:
	uint16_t port_ = 0;
};

#pragma pack(push, 1)
struct TcpHdr final {
	static const int MinSize = 20;

	enum Flag : uint8_t {
		FIN = 0x01,
		SYN = 0x02,
		RST = 0x04,
		PSH = 0x08,
		ACK = 0x10,
		URG = 0x20,
		ECE = 0x40,
		CWR = 0x80
	};

	uint16_t sport_;
	uint16_t dport_;
	uint32_t seq_;
	uint32_t ack_;
	uint8_t off_rsvd_;
	uint8_t flags_;
	uint16_t win_;
	uint16_t sum_;
	uint16_t urp_;

	Tcp sport() const { return Tcp(ntohs(sport_)); }
	Tcp dport() const { return Tcp(ntohs(dport_)); }

	uint32_t seq() const { return ntohl(seq_); }
	uint32_t ack() const { return ntohl(ack_); }
	uint16_t win() const { return ntohs(win_); }
	uint16_t sum() const { return ntohs(sum_); }
	uint16_t urp() const { return ntohs(urp_); }

	uint8_t off() const { return (off_rsvd_ >> 4) & 0x0F; }
	uint8_t reserved() const { return off_rsvd_ & 0x0F; }
	uint8_t len() const { return off() * 4; }

	bool fin() const { return (flags_ & FIN) != 0; }
	bool syn() const { return (flags_ & SYN) != 0; }
	bool rst() const { return (flags_ & RST) != 0; }
	bool psh() const { return (flags_ & PSH) != 0; }
	bool ackFlag() const { return (flags_ & ACK) != 0; }
	bool urg() const { return (flags_ & URG) != 0; }
	bool ece() const { return (flags_ & ECE) != 0; }
	bool cwr() const { return (flags_ & CWR) != 0; }
};
#pragma pack(pop)