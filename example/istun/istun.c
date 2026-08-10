#include <stdio.h>

#include "../../traversal/traversal.h"

int main(void) {
    printf("start istun server\n");
    int ret = init_istun();
    if (ret < 0) {
        return ret;
    }

    return 0;
}
