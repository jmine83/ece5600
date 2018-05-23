
#include <sys/socket.h>
#include <sys/types.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
	 int buffer_size = 810;
     int sockfd, newsockfd, portno;
     socklen_t clilen;
     char buffer[buffer_size];
     struct sockaddr_in serv_addr, cli_addr;
     int n;
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
        error("opening socket failed");
     bzero((char *) &serv_addr, sizeof(serv_addr));
     portno = atoi(argv[1]);
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(portno);
     if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        error("binding failed");
     listen(sockfd,5);
     clilen = sizeof(cli_addr);
     newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
     if (newsockfd < 0) 
        error("accept failed");
     bzero(buffer,buffer_size);
     n = read(newsockfd,buffer,buffer_size-1);
     if (n < 0) error("read failed");
     printf("message received: \n\n%s\n",buffer);
     if (n < 0) error("write failed");
     close(newsockfd);
     close(sockfd);
     return 0; 
}
