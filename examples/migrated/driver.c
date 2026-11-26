/* SYNTHETIC illustration. Not compiled on QNX. */
#include <secpol/ids.h>
int init_migrated_driver(void) {
    int id = InterruptAttachEvent(3, &event, 0);
    return devctl(fd, DCMD_I2C_SEND, &msg, sizeof(msg), NULL) + id;
}
