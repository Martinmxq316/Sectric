/*
Copyright (c) 2018 Xiao Wang (wangxiao@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Enquiries about further applications and development opportunities are welcome.
*/

#ifndef NETWORK_IO_CHANNEL
#define NETWORK_IO_CHANNEL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>  // 添加时间统计
#include <iostream>
#include <string>
#include <tuple>
#include "utils/io_channel.h"
using std::string;

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace sci {
/** @addtogroup IO
  @{
 */

class NetIO : public IOChannel<NetIO> {
 public:
  bool is_server;
  int mysocket = -1;
  int consocket = -1;
  FILE *stream = nullptr;
  char *buffer = nullptr;
  bool has_sent = false;
  string addr;
  int port;
  uint64_t counter = 0;
  uint64_t recv_counter = 0;
  std::chrono::duration<double> send_time = std::chrono::duration<double>::zero();
  std::chrono::duration<double> recv_time = std::chrono::duration<double>::zero();
  std::chrono::duration<double> recv_time_with_wait = std::chrono::duration<double>::zero();

  NetIO(const char *address, int port, bool quiet = false) {
    this->port = port;
    is_server = (address == nullptr);
    if (address == nullptr) {
      struct sockaddr_in dest;
      struct sockaddr_in serv;
      socklen_t socksize = sizeof(struct sockaddr_in);
      memset(&serv, 0, sizeof(serv));
      serv.sin_family = AF_INET;
      serv.sin_addr.s_addr = htonl(INADDR_ANY); /* set our address to any interface */
      serv.sin_port = htons(port);              /* set the server port number */
      mysocket = socket(AF_INET, SOCK_STREAM, 0);
      int reuse = 1;
      setsockopt(mysocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
      if (bind(mysocket, (struct sockaddr *)&serv, sizeof(struct sockaddr)) < 0) {
        perror("error: bind");
        exit(1);
      }
      if (listen(mysocket, 1) < 0) {
        perror("error: listen");
        exit(1);
      }
      consocket = accept(mysocket, (struct sockaddr *)&dest, &socksize);
      close(mysocket);
    } else {
      addr = string(address);

      struct sockaddr_in dest;
      memset(&dest, 0, sizeof(dest));
      dest.sin_family = AF_INET;
      dest.sin_addr.s_addr = inet_addr(address);
      dest.sin_port = htons(port);

      while (1) {
        consocket = socket(AF_INET, SOCK_STREAM, 0);

        if (connect(consocket, (struct sockaddr *)&dest, sizeof(struct sockaddr)) == 0) {
          break;
        }

        close(consocket);
        usleep(1000);
      }
    }
    set_nodelay();
    stream = fdopen(consocket, "wb+");
    buffer = new char[NETWORK_BUFFER_SIZE];
    memset(buffer, 0, NETWORK_BUFFER_SIZE);
    // setvbuf(stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE);
    setvbuf(stream, buffer, _IONBF, NETWORK_BUFFER_SIZE);
    if (!quiet) std::cout << "connected\n";
  }

  void sync() {
    int tmp = 0;
    if (is_server) {
      send_data(&tmp, 1);
      recv_data(&tmp, 1);
    } else {
      recv_data(&tmp, 1);
      send_data(&tmp, 1);
      flush();
    }
  }

  ~NetIO() {
    fflush(stream);
    close(consocket);
    delete[] buffer;
  }

  void set_nodelay() {
    const int one = 1;
    setsockopt(consocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  }

  void set_delay() {
    const int zero = 0;
    setsockopt(consocket, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));
  }

  void flush() { fflush(stream); }

  void send_data(const void *data, int len) {
    auto start = std::chrono::high_resolution_clock::now();  // 开始时间
    counter += len;
    int sent = 0;
    while (sent < len) {
      int res = fwrite(sent + (char *)data, 1, len - sent, stream);
      if (res >= 0)
        sent += res;
      else
        fprintf(stderr, "error: net_send_data %d\n", res);
    }
    has_sent = true;
    auto end = std::chrono::high_resolution_clock::now();  // 结束时间
    send_time += end - start;                              // 累计发送时间
  }

  void recv_data(void *data, int len) {
    if (has_sent) fflush(stream);
    has_sent = false;

    bool started = false;  // 是否开始接收数据的标志
	std::chrono::_V2::system_clock::time_point start;
	std::chrono::_V2::system_clock::time_point start_with_wait = std::chrono::high_resolution_clock::now();
    int received = 0;
    while (received < len) {
      int res = fread(received + (char *)data, 1, len - received, stream);
      if (res > 0) {
        if (!started) {
          start = std::chrono::high_resolution_clock::now();  // 第一次接收到数据时记录开始时间
          started = true;
        }
        received += res;
      } else {
        fprintf(stderr, "error: net_recv_data %d\n", res);
      }
    }
    recv_counter += len;

    auto end = std::chrono::high_resolution_clock::now();  // 结束时间
	recv_time_with_wait+=end-start_with_wait;
    if (started) {
      recv_time += end - start;  // 累计接收时间
	//   std::cout<<is_server<<"                       ----------------------------------------------"<<std::chrono::duration_cast<std::chrono::seconds>(end-start).count()<<std::endl;
      start = end;               // 重置开始时间，以便计算下一次接收的数据
    }
  }

  std::tuple<double, double,double> get_time_statistics() {
    return std::make_tuple(send_time.count(), recv_time.count(),recv_time_with_wait.count());
  }
};
/**@}*/

}  // namespace sci
#endif  // NETWORK_IO_CHANNEL
