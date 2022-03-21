/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "server.h"
#include "Enclave_u.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>

#include "json.hpp"
#include <vector>

#define USER_LIMIT 2
#define BUFFER_SIZE 1024
#define FD_LIMIT 65535

using namespace std;

static char buf[USER_LIMIT][BUFFER_SIZE];

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void ocall_strcpy(char *Destr, char *Sostr, size_t Delen, size_t Solen)
{
    if (Delen > Solen)
        Delen = Solen;
    if (Delen)
        memcpy(Destr, Sostr, Delen);
    
}

int setnonblock(int fd)
{
    int old_option = fcntl(fd, F_GETFL);    
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}

int setreuseaddr(int fd)
{
    int on = 1;    
    int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    return ret;
}

int readn(int fd, void* buf, int n)
{
    int left = n;    
    char *ptr = (char *)buf;
    
    while (left > 0)
    {
        int len = read(fd, ptr, left);
        if (len == -1)
        {
            if (EINTR == errno)
                left = n;
            else
                return -1;
            
        }else if (len == 0)
        {
            break;
        }
        left -= len;
        ptr += len;
    }

    return n-left;
}

//返回绝对时间，以us为单位
int64_t getTime()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int64_t seconds = tv.tv_sec;

    return seconds*1000*1000 + tv.tv_usec;
}

/* Application entry */
int main(int argc, char* argv[])
{
    if (argc <= 2)
    {
        printf("usage: %s ip_address port_number\n", basename(argv[0]));
        return 1;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);

    int ret = 0;
    struct sockaddr_in address;
    bzero(&address, sizeof(address));
    address.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &address.sin_addr);
    address.sin_port = htons(port);

    int listenfd = socket(PF_INET, SOCK_STREAM, 0);
    assert(listenfd >= 0);
    ret = setreuseaddr(listenfd);
    assert(ret != -1);


    ret = bind(listenfd, (struct sockaddr*)&address, sizeof(address));
    assert(ret != -1);

    ret = listen(listenfd, 5);
    assert(ret != -1);

    pollfd fds[USER_LIMIT+1];
    int user_counter = 0;
    for (int i = 1; i <= USER_LIMIT; i++)
    {
        fds[i].fd = -1;
        fds[i].events = 0;
    }
    fds[0].fd = listenfd;
    fds[0].events = POLLIN|POLLERR;
    fds[0].revents = 0;

   while(1)
    {
        ret = poll(fds, user_counter+1, -1);
        if(ret < 0)
        {
            printf("poll failure\n");
            break;
        }

        for(int i = 0; i < user_counter + 1; i++)
        {
            if ((fds[i].fd == listenfd) && (fds[i].revents & POLLIN))
            {
                struct sockaddr_in client_addr;
                socklen_t addrlen = sizeof(client_addr);
                int connfd = accept(listenfd, (struct sockaddr*)&client_addr, &addrlen);
                if(connfd < 0)
                {
                    printf("errno is %d\n", errno);
                    continue;
                }
                if(user_counter >= USER_LIMIT)
                {
                    const char* info = "too many users\n";
                    printf("%s", info);
                    send(connfd, info, strlen(info), 0);
                    close(connfd);
                    continue;
                }

                user_counter++;
                setnonblock(connfd);

                fds[user_counter].fd = connfd;
                fds[user_counter].events = POLLIN|POLLRDHUP|POLLERR;
                fds[user_counter].revents = 0;

                printf("comes a new user, now have %d users\n", user_counter);
            }
            else if(fds[i].revents & POLLERR)
            {
                printf("get an error from %d\n", fds[i].fd);
                char errors[100];
                memset(errors, 0, 100);
                socklen_t length = sizeof(errors);
                if(getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &errors, &length) < 0)
                {
                    printf("get socket option failed\n");
                }
                continue;
            }
            else if(fds[i].revents & POLLRDHUP)
            {
                close(fds[i].fd);
                fds[i] = fds[user_counter];
                i--;
                user_counter--;
                printf("a client left\n");

            }
            else if(fds[i].revents & POLLIN)
            {
                int connfd = fds[i].fd;
                int len = 0;
                ret = recv(connfd, &len, 4, 0);
//                printf("get %d bytes of client data %s from %d\n", ret, recvBuf, connfd);

                if (ret < 0)
                {
                    if(errno != EAGAIN)
                    {
                        close(connfd);
                        fds[i] = fds[user_counter];
                        i--;
                        user_counter--;
                    }
                }
                else if (ret == 0)
                {
                }
                else
                {
//此处进入sgx生成public key并打包发送
                    char buffer[BUFFER_SIZE] = {0};
                    ret = readn(connfd,buffer,len);
                    if (ret != len) 
                    {
                        close(connfd);
                        fds[i] = fds[user_counter];
                        i--;
                        user_counter--;
                        continue;
                    }
                        
                    string recvMsg(buffer);
                    nlohmann::json j = nlohmann::json::parse(recvMsg);
                    int type = j["type"];
                    int result = 0;
                    int64_t start_time, end_time;
                    string message;
                    char pubA[65] = {0};
                    nlohmann::json jsdic;
                    switch(type)
                    {
                        case 1:
                            start_time = getTime();

                            /* Initialize the enclave */
                            if(initialize_enclave() < 0){
                                printf("enclave intialize error\n");
                                result = 500;
                                break;
                            }
                            /* Utilize edger8r attributes */
                            edger8r_array_attributes();
                            edger8r_pointer_attributes();
                            edger8r_type_attributes();
                            edger8r_function_attributes();

                            /* Utilize trusted libraries */
                            ecall_libc_functions();
                            ecall_libcxx_functions();
                            ecall_thread_functions();
                         
                            //64字节公钥
                            secret_sharing(global_eid, pubA, 11, 3);

                            
                            printf("pubA=%s\n",pubA);

                            /* Destroy the enclave */
                            sgx_destroy_enclave(global_eid);
                            
                            printf("Info: SampleEnclave successfully returned.\n");

                            result = 200;
                            jsdic["type"] = 2;
                            jsdic["result"] = result;
                            jsdic["publickey"] = vector<char>(pubA, pubA+65);
                        break; 

                        case 3:

                        break; 
                        case 4:

                        break; 
                        default:

                        break; 
                    }


                    //将结果打包放到缓冲区准备发送
                    end_time = getTime();
                    jsdic["starttime"] = start_time;
                    jsdic["endtime"] = end_time;
                    printf("message is %s\n", pubA);

                    string msg = jsdic.dump();
                    memset(buf[i], 0, BUFFER_SIZE);
                    snprintf(buf[i], msg.size()+1,"%s",msg.c_str());

                    fds[i].events |= POLLOUT;
                }
            }
            else if(fds[i].revents & POLLOUT)
            {
                int connfd = fds[i].fd;

                int len = strlen(buf[i]);
                ret = send(connfd, &len, 4, 0);
                ret = send(connfd, buf[i], len, 0);
                fds[i].events = POLLIN|POLLRDHUP|POLLERR;
            }
        }
    }

    close(listenfd);
    return 0;
}
