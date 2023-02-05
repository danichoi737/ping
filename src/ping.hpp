/*
 *  Ping class
 */

#include <netdb.h>
#include <linux/types.h>
#include <sys/capability.h>

/*
 *  Socket structrue
 */
typedef struct socket_st {
  int fd;
  int socktype;
} socket_st;

/*
 *  Ping runtime state
 */
struct PingRTS {
  int interval;    // Interval between packets (msec)
  uid_t uid;       // User ID
  cap_value_t cap_raw;
  cap_value_t cap_admin;
};

class Ping
{
private:
  socket_st socket_ipv4_;
  addrinfo hints_;
  PingRTS *rts_;
  void limitCapabilities(PingRTS *rts);
  int modifyCapability(cap_value_t, cap_flag_value_t);
  int disableCapabilityRaw();
  int enableCapabilityRaw();
  void createSocket(PingRTS *rts, socket_st *sock, int family, int socktype, int protocol, int requisite);

public:
  Ping() = default;
  ~Ping() = default;
  int init();
};
