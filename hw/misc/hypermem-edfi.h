#ifndef HYPERMEM_EDFI_H
#define HYPERMEM_EDFI_H

/* from llvm-apps: llvm/include/edfi/common.h */

#ifndef PACKED
#define PACKED __attribute__((aligned(8),packed))
#endif

#define EDFI_DFLIB_PATH_MAX                     (512)
#define EDFI_CANARY_VALUE                       0xFF0A0011

typedef unsigned long long exec_count;
typedef struct {
    char *name;
    int *bb_num_injected;
    int *bb_num_candidates;
} fault_type_stats;

typedef struct {
    float fault_prob;
    int min_fdp_interval;
    int faulty_bb_index;
    unsigned int min_fault_time_interval;
    unsigned int max_time;
    unsigned long long max_faults;
    unsigned int rand_seed;
    char dflib_path[EDFI_DFLIB_PATH_MAX];
} PACKED edfi_context_conf_t;

typedef struct {
    unsigned int canary_value1;
    int fault_fdp_count;
    unsigned long long fault_time;
    unsigned long long start_time;
    unsigned long long total_faults;
    fault_type_stats *fault_type_stats;
    exec_count *bb_num_executions;
    int *bb_num_faults;
    unsigned int num_bbs;
    unsigned int num_fault_types;
    int no_svr_thread;
    char *output_dir;
    int num_requests_on_start;
    int verbosity;
    edfi_context_conf_t c;
    unsigned int canary_value2;
} PACKED edfi_context_t;

#endif /* !defined(HYPERMEM_EDFI_H) */
