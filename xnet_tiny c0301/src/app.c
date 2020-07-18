#include <stdio.h>
#include "xnet_tiny.h"

int main(void) {
	xnet_init();

	printf("xnet is running...\n");

	while (1) {
		xnet_poll();
	}
	
	return 0;
}
