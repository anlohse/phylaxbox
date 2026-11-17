#include <iostream>
#include "config.h"

int main(int argc, char **argv) {
	std::cout << "Hello World" << std::endl;
	std::cout << "Version " << browser_connector_VERSION_MAJOR << "." << browser_connector_VERSION_MINOR << std::endl;
	return 0;
}
