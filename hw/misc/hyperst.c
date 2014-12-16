#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"
#include "qemu/config-file.h"
#include "qemu/option.h"

#include "helper.h"
#include "exec/softmmu_exec.h"

#include <qemu/hypermem-api.h>

#include <pthread.h>
#include "hyperst.h"
#include "hypermem.h"

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define LISTEN_BACKLOG 1024

static int clients_nr;

static int handle_connection(HyperMemState *state, int connfd, struct sockaddr_in addr)
{
    int ret;
    struct hyper_message header;
    struct hyper_message reply;

    ret = recv (connfd, &header, sizeof(struct hyper_message), 0);
    if (ret != sizeof(struct hyper_message)) {
        return -1;
    }

    switch (header.type) {
        case HYPERTYPE_CHECK:
            /* If we have the context associated with the name we reply */
            if (magic_context_find(state, header.target) != NULL) {
                reply.type = HYPERTYPE_REPLY;
                reply.payload_size = 0;
                memcpy(reply.target, header.target, MAX_TARGET_NAME);
                send (connfd, &reply, sizeof(struct hyper_message), 0);
                break;
            }
            /* Fallthrough and error */

        /* If we get here, we reply with an error due to unhandled message*/
        default:
            reply.type = HYPERTYPE_ERROR;
            reply.payload_size = 0;
            send (connfd, &reply, sizeof(struct hyper_message), 0);
            break;
    }
    return 0;
}

/*
 * The main loop for the hyperst_server is responsible for running as long as we have
 * running hyperst clients(in the current implementation)
 */
static void *hyperst_server(void *arg)
{
    int ret;
    int sockfd, peerfd;
    struct sockaddr_in serv_addr, peer_addr;
    HyperMemState *state = arg;

    socklen_t peer_addr_size;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        handle_error("hypermem: Failed to create socket for magic_st server");
    }

    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    /* Starting the server on all ip addresses and port 0xedf1 which whould be around 60000 */
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(0xedf1);

    ret = bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr_in));
    if (ret == -1) {
        handle_error("hypermem: Bind has failed to attach to port");
    }

    ret = listen(sockfd, LISTEN_BACKLOG);
    if (ret == -1) {
        handle_error("hypermem: Failed to set listen flag to socket");
    }

    while(clients_nr) {
        peer_addr_size = sizeof(peer_addr);
        peerfd = accept(sockfd, (struct sockaddr *) &peer_addr,
                        &peer_addr_size);
        if (peerfd == -1) {
            handle_error("hypermem: Failed to accept connection");
        }

        ret = handle_connection(state, peerfd, peer_addr);
        if (ret != 0) {
            handle_error("hypermem: Failed to handle connection");
        }
    }

    return NULL;
}

int start_hyperst_client(HyperMemState *state, char *path, char *target)
{
    int ret;
    pthread_attr_t attr;
    static pthread_t server_thread_id;

    if (clients_nr == 0) {
        clients_nr ++;
        ret = pthread_attr_init(&attr);
        if (ret != 0) {
            handle_error("hypermem: Failed to init pthread_attr");
        }

        ret = pthread_create(&server_thread_id, &attr, &hyperst_server, (void *)state);
        if (ret != 0) {
            handle_error("hypermem: Failed to spawn server thread");
        }

    }
    ret = fork();
    /* The child process will be solely used to spawn a hyperst client */
    if (ret == 0) {
        /* TODO: Set this automatically to the correct values without hard-coding stuff */
        char *argv[4];
        char *environ[] = { NULL };

        argv[0] = strdup("hyperst_client");
        argv[1] = strdup("127.0.0.1");
        argv[2] = strdup("60913");
        argv[3] = target;

        execve(path, argv, environ);
        handle_error("hypermem: catstrophic error while doing execve");
    }
    return 0;
}
