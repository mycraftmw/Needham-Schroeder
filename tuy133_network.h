/*
 * @Author: Tongyu Yue 
 * @Date: 2018-11-08 15:52:20 
 * @Last Modified by: Tongyu Yue
 * @Last Modified time: 2018-11-08 16:20:19
 */

#ifndef TUY133_NETWORK_INCLUDED
#define TUY133_NETWORK_INCLUDED

#include <stdint.h>

int tuy133_connect_server(unsigned char *ip, uint16_t port);

int tuy133_send(int sock, int len, unsigned char *data);

int tuy133_read(int sock, int len, unsigned char *data);

int tuy133_close(int sock);

#endif