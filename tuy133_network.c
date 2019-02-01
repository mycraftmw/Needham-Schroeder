/*
 * @Author: Tongyu Yue 
 * @Date: 2018-11-08 16:10:28 
 * @Last Modified by: Tongyu Yue
 * @Last Modified time: 2018-11-08 18:01:40
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int tuy133_connect_server(unsigned char *ip, uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &servaddr.sin_addr);
    connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));
    return sock;
}

int tuy133_send(int sock, int len, unsigned char *data) {
    return send(sock, data, len, 0) < 0;
}

int tuy133_read(int sock, int len, unsigned char *data){
    return recv(sock, data, len, 0) < 0;
}

int tuy133_close(int sock) {
    return close(sock);
}