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

  sockaddr_in whereto;  // Who to ping
  char *hostname;

  int optlen;
  size_t datalen;

  bool timing { false };
};

class Ping
{
private:
  static constexpr size_t DEFDATALEN { 64 - 8 };  // Default data length
  static constexpr int MAXIPLEN { 60 };
  static constexpr int MAXICMPLEN { 76 };

  char *target_;
  socket_st socket_ipv4_;
  addrinfo hints_;
  addrinfo *info_result_;
  PingRTS *rts_;
  int packetlen_;
  void limitCapabilities(PingRTS *rts);
  void dropCapabilities();
  int modifyCapability(cap_value_t, cap_flag_value_t);
  int disableCapabilityRaw();
  int enableCapabilityRaw();
  void createSocket(PingRTS *rts, socket_st *sock, int family, int socktype, int protocol, int requisite);

public:
  Ping() = default;
  ~Ping() = default;
  int init(char *target);
  void run();
};
