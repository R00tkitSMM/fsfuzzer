/*
    build: path_to_custom_clang/../clang -fsanitize=fuzzer -isysroot $(xcrun
   --show-sdk-path) hello.mm -o meysam
*/

#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>



// ===============================================================
// Pishi coverage collector interface
// ===============================================================

#define DEVICE_NAME "/dev/pishi"
#define PISHI_IOCTL_MAP _IOR('K', 8, struct pishi_buf_desc)
#define PISHI_IOCTL_START _IOW('K', 10, pid_t)
#define PISHI_IOCTL_STOP _IO('K', 20)
#define PISHI_IOCTL_UNMAP _IO('K', 30)

static int pishi_fd;

extern "C" char _pishi_libfuzzer_coverage[32 << 10];
char _pishi_libfuzzer_coverage[32 << 10];

struct pishi_buf_desc {
  uintptr_t ptr;
  size_t sz;
};

struct pishi {
  unsigned long kcov_pos;
  uintptr_t kcov_area[0];
};

static struct pishi_buf_desc mc = {0};

// This is used to collect coverage data for LibFuzzer
// It is defined in the C++ code, but we need it here for the C interface
// this can't be static because it needs to be accessible from the C++ code
// libfuzzer

static void pishi_init() {
  pishi_fd = open(DEVICE_NAME, O_RDWR);
  if (pishi_fd == -1) {
    printf("open /dev/pishi");
    exit(1);
  }
  if (ioctl(pishi_fd, PISHI_IOCTL_MAP, &mc) == -1) {
    printf("PISHI_IOCTL_MAP");
    exit(1);
  }
}

static void pishi_start() {

  pid_t pid = getpid();
  printf("Starting Pishi coverage collection for PID %d\n", pid);
  if (ioctl(pishi_fd, PISHI_IOCTL_START,&pid) == -1) {
    printf("PISHI_IOCTL_START");
    exit(1);
  }
}


static void pishi_collect() {
  struct pishi *coverage = (struct pishi *)mc.ptr;
  for (int i = 0; i < coverage->kcov_pos; i++) {
    uint64_t pc = coverage->kcov_area[i];
    _pishi_libfuzzer_coverage[pc % sizeof(_pishi_libfuzzer_coverage)]++;
    printf("PC: 0x%016llx\n", pc);
  }
}

static void pishi_stop() {
  if (ioctl(pishi_fd, PISHI_IOCTL_STOP) == -1) {
    printf("PISHI_IOCTL_STOP");
    exit(1);
  }
  pishi_collect();
}

static void pishi_unmap() {
  if (ioctl(pishi_fd, PISHI_IOCTL_UNMAP) == -1)
    printf("PISHI_IOCTL_UNMAP");
  close(pishi_fd);
}


#include <stdio.h>
#include <mach/mach.h>

typedef struct {
    mach_msg_header_t header;
    char data[256];
} simple_msg_t;

int main() {
  pishi_init();
  pishi_start();
  // uintptr_t** a = (uintptr_t**)&data;
  // ioctl(pishi_fd, PISHI_IOCTL_FUZZ, a);
  open(".", 0, 0);

  
  // mach_port_t remote_port = 12345; // <-- replace with receiver port

  //   simple_msg_t msg;

  //   msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  //   msg.header.msgh_size = sizeof(msg);
  //   msg.header.msgh_remote_port = remote_port;
  //   msg.header.msgh_local_port = MACH_PORT_NULL;
  //   msg.header.msgh_id = 0;

  //   strcpy(msg.data, "Hello from sender");

  //   mach_msg(
  //       &msg.header,
  //       MACH_SEND_MSG,
  //       msg.header.msgh_size,
  //       0,
  //       MACH_PORT_NULL,
  //       MACH_MSG_TIMEOUT_NONE,
  //       MACH_PORT_NULL
  //   );
  

  pishi_stop();

  return 0;
}



   