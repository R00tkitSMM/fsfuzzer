#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  const char *path = "/tmp/aio_write_poc.bin";
  char msg[] = "aio_write poc payload\n";

  int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  struct aiocb cb;
  memset(&cb, 0, sizeof(cb));
  cb.aio_fildes = fd;
  cb.aio_buf = msg;
  cb.aio_nbytes = strlen(msg);
  cb.aio_offset = 0;

  if (aio_write(&cb) != 0) {
    perror("aio_write");
    close(fd);
    return 1;
  }

  const struct aiocb *list[1] = {&cb};
  if (aio_suspend(list, 1, NULL) != 0) {
    perror("aio_suspend");
    (void)aio_cancel(fd, &cb);
    close(fd);
    return 1;
  }

  int err = aio_error(&cb);
  if (err != 0) {
    errno = err;
    perror("aio_error");
    (void)aio_cancel(fd, &cb);
    close(fd);
    return 1;
  }

  ssize_t written = aio_return(&cb);
  if (written < 0) {
    perror("aio_return");
    close(fd);
    return 1;
  }

  if (aio_fsync(O_SYNC, &cb) != 0) {
    perror("aio_fsync");
    close(fd);
    return 1;
  }

  printf("aio_write completed: %zd bytes -> %s\n", written, path);
  close(fd);
  return 0;
}
