// XPC Service Probe - connects, sends messages, reports results
// Built and cached by cb probe command
//
// Usage: probe_xpc <service_name> [--enumerate <start> <end>] [--key <key>] [--timeout <secs>]

#import <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void print_json_start(void) { printf("###CB_JSON_START###\n"); }
static void print_json_end(void) { printf("###CB_JSON_END###\n"); }

typedef struct {
    const char *service;
    const char *key;
    int timeout;
    int enumerate;
    int range_start;
    int range_end;
} probe_config;

static xpc_object_t send_probe(xpc_connection_t conn, int64_t msg_id,
                                const char *key, int timeout_sec) {
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(msg, key, msg_id);

    __block xpc_object_t reply_obj = NULL;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    xpc_connection_send_message_with_reply(conn, msg,
        dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
        ^(xpc_object_t reply) {
            if (reply) reply_obj = reply;
            dispatch_semaphore_signal(sem);
        });

    long result = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_sec * NSEC_PER_SEC));

    if (result != 0) return NULL; // timeout
    return reply_obj;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            fprintf(stderr, "Usage: probe_xpc <service> [--enumerate <start> <end>] "
                           "[--key <key>] [--timeout <secs>]\n");
            return 1;
        }

        probe_config cfg = {
            .service = argv[1],
            .key = "message",
            .timeout = 2,
            .enumerate = 0,
            .range_start = 0,
            .range_end = 0,
        };

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--enumerate") == 0 && i + 2 < argc) {
                cfg.enumerate = 1;
                cfg.range_start = atoi(argv[i + 1]);
                cfg.range_end = atoi(argv[i + 2]);
                i += 2;
            } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
                cfg.key = argv[++i];
            } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
                cfg.timeout = atoi(argv[++i]);
            }
        }

        // Connect
        xpc_connection_t conn = xpc_connection_create_mach_service(
            cfg.service, NULL, 0);

        __block BOOL connection_error = NO;
        xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
            if (xpc_get_type(event) == XPC_TYPE_ERROR) {
                connection_error = YES;
            }
        });
        xpc_connection_resume(conn);

        // Brief pause to detect immediate errors
        usleep(100000); // 100ms

        print_json_start();
        printf("{");
        printf("\"service\": \"%s\", ", cfg.service);

        if (connection_error) {
            printf("\"status\": \"error\", \"detail\": \"connection_failed\"");
            printf("}");
            print_json_end();
            return 1;
        }

        if (!cfg.enumerate) {
            // Simple probe: send empty dict
            xpc_object_t reply = send_probe(conn, 0, cfg.key, cfg.timeout);
            if (reply) {
                if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
                    printf("\"status\": \"error\", \"detail\": \"xpc_error\"");
                } else {
                    const char *desc = xpc_copy_description(reply);
                    printf("\"status\": \"alive\", \"reply_type\": \"dictionary\"");
                    // Don't print full reply - could be huge
                }
            } else {
                printf("\"status\": \"timeout\"");
            }
        } else {
            // Enumerate message IDs
            printf("\"status\": \"enumerate\", \"results\": [");
            int first = 1;
            for (int64_t id = cfg.range_start; id <= cfg.range_end; id++) {
                if (!first) printf(", ");
                first = 0;

                xpc_object_t reply = send_probe(conn, id, cfg.key, cfg.timeout);
                if (!reply) {
                    printf("{\"id\": %lld, \"result\": \"timeout\"}", id);
                } else if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
                    if (reply == XPC_ERROR_CONNECTION_INVALID) {
                        printf("{\"id\": %lld, \"result\": \"crash\"}", id);
                        // Service crashed - reconnect
                        conn = xpc_connection_create_mach_service(
                            cfg.service, NULL, 0);
                        xpc_connection_set_event_handler(conn, ^(xpc_object_t e) {});
                        xpc_connection_resume(conn);
                        usleep(500000); // wait for restart
                    } else {
                        printf("{\"id\": %lld, \"result\": \"error\"}", id);
                    }
                } else {
                    printf("{\"id\": %lld, \"result\": \"success\"}", id);
                }
                fflush(stdout);
            }
            printf("]");
        }

        printf("}");
        print_json_end();
    }
    return 0;
}
