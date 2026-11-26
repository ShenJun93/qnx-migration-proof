/* SYNTHETIC fixture. Not compiled on QNX. */
#include <login.h>
int init_legacy_driver(void) {
    int id = InterruptAttach(3, legacy_handler, 0, 0, 0);
    return devctl(fd, DCMD_I2C_MASTER_SEND, &msg, sizeof(msg), NULL) + id;
}
