#ifndef COMMON_H
#define COMMON_H

struct ps_conf_t
{
    char *comm;
    char *args;
};

typedef struct ps_conf_t ps_conf_t;

struct ps_t 
{
    unsigned int pid;
    ps_conf_t *ps_conf;
};

typedef struct ps_t ps_t;

typedef struct tree_node_t tree_node_t;

struct tree_node_t 
{
    char *node_name;
    ps_t *data;
    tree_node_t *first_child;
    tree_node_t *next_sibling;
};

#endif
