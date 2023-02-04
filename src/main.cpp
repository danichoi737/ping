/*
 *  main
 */

#include <iostream>
#include <getopt.h>
#include <stdlib.h>

#include "ping.hpp"

int main(int argc, char **argv)
{
  char *target {};

  // Parse command line options
  int opt {};
  while ((opt = getopt(argc, argv, "h?" "V")) != EOF) {
    switch (opt) {
    case 'V':
      std::cout << "PING v0.1.0" << std::endl;
      exit(EXIT_SUCCESS);
      break;

    default:
      break;
    }
  }
  argc -= optind;
  argv += optind;

  if (argc == 0) {
    std::cerr << "Usage error" << std::endl;
    // TO-DO: print usage
    exit(2);
  }

  // Save the target IP address from argv
  target = argv[argc - 1];

  Ping *ping = new Ping();
  ping->init();
}
