/*
 *  Ping class
 */

#include <iostream>
#include <system_error>
#include <sys/prctl.h>
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


/*
 *  Public
 */
int Ping::init(char *target)
{
  int _result { 0 };

  socket_ipv4_.fd = AF_INET;

  // Assign values to addrinfo members
  hints_.ai_flags = AI_CANONNAME;
  hints_.ai_family = AF_UNSPEC;
  hints_.ai_socktype = SOCK_DGRAM;
  hints_.ai_protocol = IPPROTO_UDP;

  rts_ = new PingRTS;
  rts_->interval = 1000;

  limitCapabilities(rts_);

  hints_.ai_family = AF_INET;

  _result += enableCapabilityRaw();

  createSocket(rts_, &socket_ipv4_, AF_INET, hints_.ai_socktype, IPPROTO_ICMP, hints_.ai_family == AF_INET);

  _result += disableCapabilityRaw();

  _result += getaddrinfo(target, nullptr, &hints_, &info_result_);

  return _result;
}
