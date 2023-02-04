/*
 *  Ping class
 */

#include <netdb.h>
#include <linux/types.h>
#include <sys/capability.h>

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
  addrinfo hints_;
  PingRTS *rts_;
  void limitCapabilities(PingRTS *rts);
  int modifyCapability(cap_value_t, cap_flag_value_t);
  int disableCapabilityRaw();
  int enableCapabilityRaw();

public:
  Ping() = default;
  ~Ping() = default;
  int init();
};
