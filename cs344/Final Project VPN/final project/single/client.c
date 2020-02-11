#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <termios.h>

#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client"

struct sockaddr_in peerAddr;
struct addrinfo hints, *result;
int PORT_NUMBER = 55555;
const char *hostname;

int getch() {
    struct termios oldtc;
    struct termios newtc;
    int ch;
    tcgetattr(STDIN_FILENO, &oldtc);
    newtc = oldtc;
    newtc.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newtc);
    ch=getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldtc);
    return ch;
}

int createTunDevice() {
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);
    
    return tunfd;
}

SSL* setupTLSClient(const char* hostname,  SSL_CTX* ctx)
{
    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    
    SSL_METHOD *meth;
    SSL* ssl;
    
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
        printf("Error setting the verify locations. \n");
        exit(0);
    }
    ssl = SSL_new (ctx);
    
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
    
    return ssl;
}

int connectToTCPServer(const char *hostname){
    
    //get host IP address
    hints.ai_family = AF_INET;
    int error = getaddrinfo(hostname, NULL, &hints, &result);
    if (error) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        exit(1);
    }
    struct sockaddr_in* ip = (struct sockaddr_in *) result->ai_addr;
    
    // Create a TCP socket
    int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    memset(&peerAddr, 0, sizeof(peerAddr));
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(PORT_NUMBER);
    peerAddr.sin_addr.s_addr = inet_addr((char *)inet_ntoa(ip->sin_addr));
    
    connect(sockfd, (struct sockaddr*) &peerAddr,
            sizeof(peerAddr));
    
    return sockfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];
    
    //printf("Got a packet from TUN\n");
    
    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    SSL_write (ssl, buff, sizeof(buff)-1);
}

void socketSelected (int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];
    
    // printf("Got a packet from the tunnel\n");
    
    bzero(buff, BUFF_SIZE);
    int err = SSL_read (ssl, buff, sizeof(buff)-1);
    buff[err] = '\0';
    write(tunfd, buff, err);
}

void startVPN (int sockfd, SSL* ssl) {
    int tunfd  = createTunDevice();
    while (1) {
        fd_set readFDSet;
        
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        
        if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
        if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
    }
}


int main (int argc, char * argv[]) {
    
    const char *hostname;
    SSL_CTX *ctx;
    int tunfd, sockfd;
    
    if (argc > 1) hostname = argv[1];
    else {
        printf("Please enter a legal host name.\n");
        return 0;
    }
    if (argc > 2) PORT_NUMBER = atoi(argv[2]);
    
    //TLS initialization
    SSL *ssl = setupTLSClient(hostname, ctx);
    
    //create a TCP conncetion
    sockfd = connectToTCPServer(hostname);
    
    //TLS handshake
    char readbuf[2000];
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl); CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
    
    err = SSL_write (ssl, "Connect to Server!", strlen("Connect to Server!"));
    err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
    readbuf[err] = '\0';
    printf("receive: %s\n", readbuf);
    
    //user verification
    char username[20];
    char password[20];
    char check[10];
    err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
    readbuf[err] = '\0';
    printf("%s\n", readbuf);
    
    scanf("%s", username);
    err = SSL_write (ssl, username, sizeof(username));
    
    err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
    readbuf[err] = '\0';
    printf("%s\n", readbuf);
    
    //hide user password
    int ch, i = 0;
    ch = getch();
    for(;;){
        ch = getch();
        if(ch == '\n') {
            password[i] = '\0';
            break;
        }
        else {
            password[i] = (char)ch;
            i++;
        }
    }
    err = SSL_write (ssl, password, sizeof(password));
    
    err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
    strncpy(check, readbuf, sizeof(readbuf));
    if (strcmp(check, "ok") == 0){
        printf("Verification passed!\n");
    }
    else {
        printf("Verification failed, disconnected!\n");
        close(sockfd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        exit(0);
    }
    
    
    
    startVPN(sockfd, ssl);
    //Establishing tunnel in child process
    
   	close(sockfd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    
    
    // int fd[2], nbytes;
    // pid_t pid;
    // pipe(fd);
    
    // if((pid = fork()) == -1) {
    //     perror("fork");
    //     exit(1);
    // }
    // if(pid>0) { //parent process
    //   close(fd[0]); // Close the input end of the pipe.
    
    
    
    
    
    // }
    // else { //child process
    //    close(fd[1]); // Close the output end of the pipe.
    
    
    
    
    
    // }  
    
}

