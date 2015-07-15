#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"
#include "qemu/config-file.h"
#include "qemu/option.h"

#include <qemu/hypermem-api.h>

#include <pthread.h>
#include "hyperst.h"
#include "hypermem.h"

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define LISTEN_BACKLOG 1024

CPUState *hyperst_cpu;

static void handle_connection(HyperMemState *state, int connfd, struct sockaddr_in addr)
{
    int ret;
    char *payload_buff;
    struct HyperMemMagicContext *mc;
    struct hyper_message req;
    struct hyper_message *reply;
    struct hyper_region req_range;

    /* TODO: Make things more consistent and nice, since we have a mess on our hands right now */
    while (1) {
        /* TODO: exit the loop properly (not the fact that the endpoint is closed and recv fails) */
        ret = recv (connfd, &req, sizeof(struct hyper_message), 0);
        if (ret != sizeof(struct hyper_message)) {
            return;
        }

        switch (req.header.type) {
            case HYPERTYPE_GET_MAGIC_VARS:
                mc = magic_context_find(state, req.header.target);
                if ( mc == NULL) {
                    goto error_out;
                }
 
                payload_buff = magic_get_vars_with_context(state, mc);
                if (payload_buff == NULL) {
                    fprintf(stderr, "hyperst_server: Failed to read _MAGIC_VARS\n");
                    goto error_out;
                }
                /* The payload size is equal to the size of the magic_vars struct */
                reply = calloc(sizeof(struct hyper_message) + mc->_magic_vars_size, 1);
                reply->header.type = HYPERTYPE_REPLY;
                memcpy(reply->header.target, req.header.target, MAX_TARGET_NAME);
                reply->payload_size = mc->_magic_vars_size;
                memcpy(&reply->payload, payload_buff, reply->payload_size);
                if (send (connfd, reply, sizeof(struct hyper_message) + reply->payload_size, 0) < 0) {
                    fprintf(stderr, "hyperst_server: Failed to send GET_MAGIC_VARS"
                            " reply: %s\n", strerror(errno));
                    return;
                }
                /* We need to free magic_vars_buf since no one else will */
                free(payload_buff);
                break;

            case HYPERTYPE_GET_DATA_REGION:
                mc = magic_context_find(state, req.header.target);
                if ( mc == NULL) {
                    goto error_out;
                }
                ret = recv (connfd, &req_range, sizeof(struct hyper_region), 0);
                if (ret != sizeof(struct hyper_region)) {
                    fprintf(stderr, "hyperst_server: Failed to recv GET_DATA_REGION"
                            " region: %d %s\n", ret, strerror(errno));
                    goto error_out;
                }
                payload_buff = magic_get_range_with_context(state, mc, req_range.address, req_range.size);
                if (payload_buff == NULL) {
                    fprintf(stderr, "hyperst_server: Failed to read range %x + %x\n", 
                            req_range.address, (uint32_t)req_range.size);
                    goto error_out;
                }
                /* The payload size is equal to the size of the magic_vars struct */
                reply = calloc(sizeof(struct hyper_message) + req_range.size, 1);
                reply->header.type = HYPERTYPE_REPLY;
                memcpy(reply->header.target, req.header.target, MAX_TARGET_NAME);
                reply->payload_size = req_range.size;
                memcpy(&reply->payload, payload_buff, reply->payload_size);
                if (send (connfd, reply, sizeof(struct hyper_message) + reply->payload_size, 0) < 0) {
                    fprintf(stderr, "hyperst_server: Failed to reply to GET_DATA_REGION"
                            " reply: %s\n", strerror(errno));
                    return;
                }
                /* We need to free magic_vars_buf since no one else will */
                free(payload_buff);
                break;

            case HYPERTYPE_CHECK:
                /* If we have the context associated with the name we reply */
                if (magic_context_find(state, req.header.target) != NULL) {
                    reply = calloc(sizeof(struct hyper_message), 1);
                    reply->header.type = HYPERTYPE_REPLY;
                    reply->payload_size = 0;
                    memcpy(reply->header.target, req.header.target, MAX_TARGET_NAME);
                    if (send (connfd, reply, sizeof(struct hyper_message), 0) < 0) {
                        fprintf(stderr, "hyperst_server: Failed to send HYPERTYPE_REPLY"
                                " msg: %s\n", strerror(errno));
                        return;
                    }
                    break;
                }
                goto error_out;

            /* If we get here, we reply with an error due to unhandled message*/
            default:
               goto error_out;
        }
        free (reply);
    }

    close(connfd);
    return;

error_out:
    reply = calloc(sizeof(struct hyper_message), 1);
    reply->header.type = HYPERTYPE_ERROR;
    memcpy(reply->header.target, req.header.target, MAX_TARGET_NAME);
    reply->payload_size = 0;
    if (send (connfd, reply, sizeof(struct hyper_message), 0) < 0) {
        fprintf(stderr, "hyperst_server: Failed to send HYPERTYPE_ERROR"
                " msg: %s\n", strerror(errno));
    }

    close(connfd);
    free(reply);
    return;
}

/*
 * The main loop for the hyperst_server is responsible for running as long as we have
 * running hyperst clients(in the current implementation)
 */
static void *hyperst_server(void *arg)
{
    int ret;
    int optval;
    int sockfd, peerfd;
    struct sockaddr_in serv_addr, peer_addr;
    HyperMemState *state = arg;

    /* Borrow the qemu CPU from the calling thread */
    current_cpu = hyperst_cpu;


    socklen_t peer_addr_size;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        handle_error("hyperst_server: Failed to create socket server");
    }
    /* We need to set SO_REUSEADDR if this is not the first st because the socket will be in timewait */
    optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    /* Starting the server on all ip addresses and port 0xedf1 which whould be around 60000 */
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(0xedf1);

    ret = bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr_in));
    if (ret == -1) {
        handle_error("hyperst_server: Bind has failed to attach to port");
    }

    ret = listen(sockfd, LISTEN_BACKLOG);
    if (ret == -1) {
        handle_error("hyperst_server: Failed to set listen flag to socket");
    }

    peer_addr_size = sizeof(peer_addr);
    peerfd = accept(sockfd, (struct sockaddr *) &peer_addr,
                        &peer_addr_size);
    if (peerfd == -1) {
        handle_error("hyperst_server: Failed to accept connection");
    }

    handle_connection(state, peerfd, peer_addr);

    close(sockfd);
    fprintf(stderr, "hyperst_server: closing server thread\n");

    return NULL;
}

int start_hyperst(HyperMemState *state, char *path, char *target)
{
    int ret;
    pthread_attr_t attr;
    static pthread_t server_thread_id;

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        handle_error("hyperst: Failed to init pthread_attr");
    }

    hyperst_cpu = current_cpu;
    ret = pthread_create(&server_thread_id, &attr, &hyperst_server, (void *)state);
    if (ret != 0) {
        handle_error("hyperst: Failed to spawn server thread");
    }

    ret = fork();
    /* The child process will be solely used to spawn a hyperst client */
    if (ret == 0) {
        /* TODO: Set this automatically to the correct values without hard-coding stuff */
        char *argv[4];
        char *environ[] = { NULL };

        argv[0] = strdup("hyperst_shell");
        argv[1] = strdup("127.0.0.1");
        argv[2] = strdup("60913");
        argv[3] = target;

        execve(path, argv, environ);
        fprintf(stderr, "%s\n", path);
        handle_error("hyperst: catastrophic error while doing execve");
    }

    /* This is really ugly, but we cannot allow qemu to continue execution and have an unconsistent state */
    ret = pthread_join(server_thread_id, NULL);
    hyperst_cpu = NULL;
    if (ret != 0) {
        fprintf(stderr, "hyperst: Failed to join with hyperst thread (%d)\n", ret);
        return -1;
    }

    return 0;
}
