#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include "Include/json.hpp"

using namespace std;

#define BUFFER_SIZE 1024

int setnonblocking(int fd)
{
    int old_option = fcntl(fd, F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}

int readn(int fd, void *vptr, int n)
{
    int nleft = n;
    int nread = 0;
    char *ptr = (char*) vptr;

    while(nleft > 0)
    {
        nread = read(fd, ptr, nleft);  
        if (nread == -1)
        {
            printf("read error"); 
            return -1;
        }else if(nread == 0)
        {
            break;
        }
        ptr += nread;
        nleft -= nread;
    }

    return n-nleft;
}

//返回绝对时间，以us为单位
int64_t getTime()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int64_t seconds = tv.tv_sec;

    return seconds*1000*1000 + tv.tv_usec;
}

int main(int argc, char* argv[])
{
	if (argc <= 2)
	{
        printf("Usage: %s ip_address port_number\n", argv[0]);
        return 1;
	}

    const char* ip = argv[1];
    int port = atoi(argv[2]);

    struct sockaddr_in srvaddr;
    bzero(&srvaddr, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &srvaddr.sin_addr);
    srvaddr.sin_port = htons(port);


    int sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if(connect(sockfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) < 0)
    {
        printf("connect error\n");    
        close(sockfd);
        return 1;
    }
    pollfd fds[1];
    fds[0].fd = sockfd;
    fds[0].events = POLLIN | POLLRDHUP | POLLOUT;
    fds[0].revents = 0;

    //打包发送数据包给server
    char read_buf[BUFFER_SIZE] = {0};
    memset(read_buf, 0, sizeof(read_buf));
    nlohmann::json jsdic;
    jsdic["type"] = 1;
    int64_t start_time = getTime();
    int64_t end_time;
    jsdic["starttime"] = start_time;

    string msg = jsdic.dump();
    snprintf(read_buf, msg.size()+1, "%s", msg.c_str());
    int ret = 0;

    while(1)
    {
        ret = poll(fds, 1, -1);
        if(ret < 0)
        {
            printf("poll failure\n"); 
            break;
        }
        if(fds[1].revents & POLLRDHUP)
        {
            printf("server close the connection\n"); 
            break;
        }
        else if (fds[0].revents & POLLOUT)
        {
            int len = strlen(read_buf);
            ret = write(sockfd, &len, 4);
            ret = write(sockfd, read_buf, len);
            fds[0].events = POLLIN | POLLRDHUP;
        }
        else if(fds[0].revents & POLLIN)
        {
            int len = 0;
            ret = read(sockfd, &len, 4);
            if (ret < 4)
            {
                printf("read error"); 
                break;
            }
            memset(read_buf, 0, sizeof(read_buf));
            ret = readn(sockfd, read_buf, len);
            end_time = getTime();
            printf("wait time is %ld\n", end_time-start_time);

            string recvMsg(read_buf);
            nlohmann::json j = nlohmann::json::parse(recvMsg);
            int type = j["type"].get<int>();
            int result;
            int64_t peer_starttime; 
            int64_t peer_endtime;
            vector<char> publicKey;
            switch(type)
            {
                case 2:
                    result = j["result"].get<int>();
                    if (result != 200){
                        printf("server result = %d\n", result);
                        break;
                    }
                    peer_starttime = j["starttime"].get<int64_t>();
                    peer_endtime = j["endtime"].get<int64_t>();
                    printf("processtime is %ld\n", peer_endtime - peer_starttime);
                    publicKey = j["publickey"].get<vector<char>>();
                    printf("public key is:");
                    for(vector<char>::iterator iter = publicKey.begin(); iter != publicKey.end(); iter++)
                        printf("%c",*iter);
                    printf("\n");
                break;
                default:
                break;
            }
        
        }

    }
    close(sockfd);
    return 0;
}
