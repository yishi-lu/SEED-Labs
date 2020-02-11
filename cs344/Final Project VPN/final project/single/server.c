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
#include <unistd.h>
#include <shadow.h>
#include <crypt.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

struct sockaddr_in peerAddr;

int login(char *user, char *passwd)
{
    struct spwd *pw;
    char *epasswd;
    pw = getspnam(user);
    if (pw == NULL) {
        return -1;
    }
    //printf("Login name: %s\n", pw->sp_namp);
    //printf("Passwd : %s\n", pw->sp_pwdp);
    epasswd = crypt(passwd, pw->sp_pwdp);
    if (strcmp(epasswd, pw->sp_pwdp)) {
        return -1;
    }
    return 1;
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

int initTCPServer() {
    struct sockaddr_in sa_server;
    int listen_sock;
    
    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset(&sa_server, 0, sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = htonl(INADDR_ANY);
    sa_server.sin_port = htons(PORT_NUMBER);
    
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    
    return listen_sock;
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
    
    //printf("Got a packet from the tunnel\n");
    
    bzero(buff, BUFF_SIZE);
    int err = SSL_read (ssl, buff, sizeof(buff)-1);
    buff[err] = '\0';
    write(tunfd, buff, err);
}

void parentSelected (int parentPipe, int sockfd, SSL *ssl){
    
    int  len;
    char buff[BUFF_SIZE];
    
    len = read(parentPipe, buff, sizeof(buff)-1);
    
    if(len > 0){
        if(buff[0] == 'q'){
            close(sockfd);
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }
}

void startVPN (int sockfd, SSL* ssl, int parentPipe) {
    
    int tunfd  = createTunDevice();
    
    while (1) {
        fd_set readFDSet;
        
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        FD_SET(parentPipe, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        
        if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
        if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
        if (FD_ISSET(parentPipe, &readFDSet)) parentSelected(parentPipe, sockfd, ssl);
    }
}

int main (int argc, char * argv[]) {
    
    //initialize TLS
    char readbuf[2000];
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;
    int err;
    int sockfd;
    
    // Step 0: OpenSSL library initialization
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    
    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    // Step 2: Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);
    // Step 3: Create a new SSL structure for a connection
    ssl = SSL_new (ctx);
    
    //setup TCP socket, waiting for connection
    struct sockaddr_in sa_client;
    size_t client_len;
    int listen_sock = initTCPServer();
    
    while(1){
        sockfd = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
        
        int fd[2];
        pid_t pid;
        pipe(fd);
        fcntl(fd[0], F_SETFL, O_NONBLOCK);
        
        if((pid = fork()) == -1) {
            perror("fork");
            exit(1);
        }
        if(pid>0) { //parent proces
            close(fd[0]); // Close the input end of the pipe.
        }
        else { //child process
            close(fd[1]); // Close the output end of the pipe.
            
            //TCP socket is ready, setup TLS section
            SSL_set_fd (ssl, sockfd);
            err = SSL_accept (ssl);
            CHK_SSL(err);
            printf ("SSL connection established!\n");
            err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
            readbuf[err] = '\0';
            printf("receive: %s\n", readbuf);
            err = SSL_write (ssl, "Connection established!", strlen("Connection established!"));
            
            //client verification
            char username[5];
            char password[5];
            err = SSL_write (ssl, "Please enter username:", strlen("Please enter username:"));
            err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
            readbuf[err] = '\0';
            
            strncpy(username, readbuf, sizeof(readbuf));
            //printf("The user enter username: %s\n", username);
            
            err = SSL_write (ssl, "Please enter password:", strlen("Please enter password:"));
            err = SSL_read (ssl, readbuf, sizeof(readbuf)-1);
            readbuf[err] = '\0';
            
            strncpy(password, readbuf, sizeof(readbuf));
            //printf("The user enters password: %s\n", password);
            
            if(login(username, password) == 1){
                printf("user verification pass!\n");
                err = SSL_write (ssl, "ok", sizeof("ok"));
            }
            else {
                printf("wrong username or password, disconnected!\n");
                err = SSL_write (ssl, "Wrong username or password, disconnected!", sizeof("Wrong username or password, disconnected!"));
                exit(0);
                
                
            }
            
            startVPN(sockfd, ssl, fd[0]);
            
            close(sockfd);
            SSL_shutdown(ssl);  
            SSL_free(ssl);
            
        } 
    }
    
}
