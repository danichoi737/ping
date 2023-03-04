/*
 *  Ping class
 */

#include <cstring>
#include <iostream>
#include <system_error>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <unistd.h>

#include "ping.hpp"

/*
 *  Private
 */
void Ping::limitCapabilities(PingRTS *rts)
{
  cap_t _cap_cur_p { nullptr };
  cap_t _cap_p { nullptr };
  cap_flag_value_t _cap_ok { CAP_CLEAR };

  // Allocates a capability state
  _cap_cur_p = cap_get_proc();
  if (_cap_cur_p == nullptr) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    exit(EXIT_FAILURE);
  }

  // Creates a capability state
  _cap_p = cap_init();
  if (_cap_p == nullptr) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    exit(EXIT_FAILURE);
  }

  // CAP_NET_ADMIN
  cap_get_flag(_cap_cur_p, CAP_NET_ADMIN, CAP_PERMITTED, &_cap_ok);
  if (_cap_ok != CAP_CLEAR) {
    cap_set_flag(_cap_p, CAP_PERMITTED, 1, &rts->cap_admin, CAP_SET);
  }
  _cap_ok = CAP_CLEAR;

  // CAP_NET_RAW
  cap_get_flag(_cap_cur_p, CAP_NET_RAW, CAP_PERMITTED, &_cap_ok);
  if (_cap_ok != CAP_CLEAR) {
    cap_set_flag(_cap_cur_p, CAP_PERMITTED, 1, &rts->cap_raw, CAP_SET);
  }

  if (cap_set_proc(_cap_p) < 0) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    exit(EXIT_FAILURE);
  }
  if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    exit(EXIT_FAILURE);
  }
  if (setuid(getuid()) < 0) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    exit(EXIT_FAILURE);
  }
  if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    exit(EXIT_FAILURE);
  }

  cap_free(_cap_p);
  cap_free(_cap_cur_p);

  rts->uid = getuid();
}

void Ping::dropCapabilities()
{
  cap_t _cap = cap_init();
  if (cap_set_proc(_cap) < 0) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    exit(EXIT_FAILURE);
  }
  cap_free(_cap);
}

int Ping::modifyCapability(cap_value_t cap, cap_flag_value_t on)
{
  cap_t _cap_p = cap_get_proc();
  cap_flag_value_t _cap_ok { CAP_CLEAR };
  int _rc { - 1 };

  if (_cap_p == nullptr) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;

    if (_cap_p) {
      cap_free(_cap_p);
    }
    return _rc;
  }

  cap_get_flag(_cap_p, cap, CAP_PERMITTED, &_cap_ok);
  if (_cap_ok == CAP_CLEAR) {
    _rc = on ? -1 : 0;
    return _rc;
  }

  cap_set_flag(_cap_p, CAP_EFFECTIVE, 1 ,&cap, on);

  if (cap_set_proc(_cap_p) < 0) {
    std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;

    if (_cap_p) {
      cap_free(_cap_p);
    }
    return _rc;
  }

  cap_free(_cap_p);
  _cap_p = nullptr;
  _rc = 0;

  if (_cap_p) {
    cap_free(_cap_p);
  }
  return _rc;
}

int Ping::disableCapabilityRaw()
{
  return modifyCapability(CAP_NET_RAW, CAP_CLEAR);
}

int Ping::enableCapabilityRaw()
{
  return modifyCapability(CAP_NET_RAW, CAP_SET);
}

void Ping::createSocket(PingRTS *rts, socket_st *sock, int family, int socktype, int protocol, int requisite)
{
  // TO-DO: add assert conditions

  if (socktype == SOCK_DGRAM) {
    sock->fd = socket(family, socktype, protocol);
  }

  // User is not allowed to use ping sockets
  if (sock->fd == -1 && errno == EACCES) {
    std::cerr << "Socket creation failed" << std::endl;
  }

  sock->socktype = socktype;

  // Valid socket
  if (sock->fd != -1) {
    return;
  }
}

int Ping::sendProbe(void *packet, unsigned int packet_size)
{
  icmphdr *_icp { nullptr };
  int _cc {};
  int _i {};

  _icp = static_cast<icmphdr *>(packet);
  _icp->type = ICMP_ECHO;
  _icp->code = 0;
  _icp->checksum = 0;
  _icp->un.echo.sequence = htons(rts_->ntransmitted + 1);
  _icp->un.echo.id = rts_->ident;  // ID

  // TO-DO: rcvd_clear()

  if (rts_->timing == true) {
    std::memset(_icp + 1, sizeof(timeval), 0);
  }

  _cc = rts_->datalen + 8;  // Skips ICMP protion

  // Compute ICMP checksum here
  // TO-DO: in_cksum()

  if (rts_->timing == true) {
    timeval _tmp_tv;
    gettimeofday(&_tmp_tv, nullptr);
    memcpy(_icp + 1, &_tmp_tv, sizeof(_tmp_tv));
    // TO-DO: in_cksum()
  }

  _i = sendto(socket_ipv4_.fd, _icp, _cc, 0, (sockaddr *)&rts_->whereto, sizeof(rts_->whereto));

  return (_cc == _i ? 0 : _i);
}

int Ping::pinger()
{
  static int _tokens {};
  int _i {};

  // Check that packets < rate * time + preload
  if (rts_->cur_time.tv_sec == 0) {
    clock_gettime(CLOCK_MONOTONIC_RAW, &rts_->cur_time);
    _tokens = rts_->interval * (rts_->preload - 1);
  } else {
    // TO-DO
  }

  // RESEND
  _i = sendProbe(rts_->outpack, sizeof(rts_->outpack));
  if (_i == 0) {
    // TO-DO: advance_ntransmitted()
    return rts_->interval - _tokens;
  }
}

void Ping::loop(uint8_t *packet)
{
  char _addrbuf[128] {};
  char _ans_data[4096] {};
  iovec _iov {};
  msghdr _msg {};
  int _cc {};
  int _next {};
  int _polling { 0 };

  while (true)
  {
    // TO-DO: Check exit conditions

    do {
      _next = pinger();
    } while (_next <= 0);

    while (true)
    {
      timeval *_recv_timep { nullptr };
      timeval _recv_time {};

      _iov.iov_base = static_cast<uint8_t *>(packet);
      _iov.iov_len = packetlen_;
      std::memset(&_msg, sizeof(_msg), 0);
      _msg.msg_name = _addrbuf;
      _msg.msg_namelen = sizeof(_addrbuf);
      _msg.msg_iov = &_iov;
      _msg.msg_iovlen = 1;
      _msg.msg_control = _ans_data;
      _msg.msg_controllen = sizeof(_ans_data);

      _cc = recvmsg(socket_ipv4_.fd, &_msg, _polling);
      _polling = MSG_DONTWAIT;

      if (_cc < 0) {
        // TO-DO
      } else {
        cmsghdr *_c;
        for (_c = CMSG_FIRSTHDR(&_msg); _c; _c = CMSG_NXTHDR(&_msg, _c)) {
          if (_c->cmsg_level != SOL_SOCKET || _c->cmsg_type != SO_TIMESTAMP) {
            continue;
          }
          if (_c->cmsg_len < CMSG_LEN(sizeof(timeval))) {
            continue;
          }
          _recv_timep = (timeval *)CMSG_DATA(_c);
        }

        // TO-DO: parse_reply()
      }
    }
  }
}


/*
 *  Public
 */
int Ping::init(char *target)
{
  int _result { 0 };
  target_ = target;

  socket_ipv4_.fd = AF_INET;

  // Assign values to addrinfo members
  hints_.ai_flags = AI_CANONNAME;
  hints_.ai_family = AF_UNSPEC;
  hints_.ai_socktype = SOCK_DGRAM;
  hints_.ai_protocol = IPPROTO_UDP;

  rts_ = new PingRTS;
  rts_->interval = 1000;
  rts_->preload = 1;
  rts_->datalen = DEFDATALEN;
  rts_->ident = -1;
  rts_->outpack = new unsigned char { static_cast<unsigned char>(rts_->datalen + 28) };

  limitCapabilities(rts_);

  hints_.ai_family = AF_INET;

  _result += enableCapabilityRaw();

  createSocket(rts_, &socket_ipv4_, AF_INET, hints_.ai_socktype, IPPROTO_ICMP, hints_.ai_family == AF_INET);

  _result += disableCapabilityRaw();

  _result += getaddrinfo(target_, nullptr, &hints_, &info_result_);

  return _result;
}

void Ping::run()
{
  std::memset(&rts_->whereto, sizeof(rts_->whereto), 0);
  rts_->whereto.sin_family = AF_INET;
  // Covert internet host address
  if (inet_aton(target_, &rts_->whereto.sin_addr) == 1) {
    rts_->hostname = target_;
  }

  int _hold { 1 };
  if (setsockopt(socket_ipv4_.fd, SOL_IP, IP_RECVERR, &_hold, sizeof(_hold))) {
    std::cerr << "Your kernel is very old." << std::endl;
  }

  if (socket_ipv4_.socktype == SOCK_DGRAM) {
    if (setsockopt(socket_ipv4_.fd, SOL_IP, IP_RECVTTL, &_hold, sizeof(_hold))) {
      std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    }
    if (setsockopt(socket_ipv4_.fd, SOL_IP, IP_RETOPTS, &_hold, sizeof(_hold))) {
      std::cerr << std::system_error(errno, std::generic_category()).what() << std::endl;
    }
  }

  // Estimate memory eaten by single socket. It is rough estimate.
  // Actually, for small datalen's it depends on kernel side a lot.
  _hold = rts_->datalen + 8;
  _hold += ((_hold + 511) / 512) * (rts_->optlen + 20 + 16 + 64 + 160);
  // sock_setbufs()

  // Can we time transfer?
  if (rts_->datalen >= static_cast<int>(sizeof(timeval))) {
    rts_->timing = true;
  }
  packetlen_ = rts_->datalen + MAXIPLEN + MAXICMPLEN;

  unsigned char *_packet;
  _packet = new unsigned char[packetlen_];

  std::cout << "PING " << rts_->hostname << " (" << inet_ntoa(rts_->whereto.sin_addr) << ") "
            << rts_->datalen << "(" << rts_->datalen + 8 + rts_->optlen + 20 << ")" << " "
            << "bytes of data." << std::endl;

  dropCapabilities();
  loop(_packet);

  delete[] _packet;
}
