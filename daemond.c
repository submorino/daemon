#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "confuse.h"
#include "common.h"

#define PID_UNDEFINED -1


int g_frequency = 10;
tree_node_t *g_tree_ps = NULL;

void free_array(char** buf, int size)
{
    if (buf != NULL) 
    {
        int i = 0;
        for ( ; i<size; i++)
        {
            free(buf[i]);
            buf[i] = NULL;
        }
    }
}

cfg_t *parse_conf(const char *filename)
{
    cfg_opt_t process_opts[] = {
        CFG_STR("comm", 0, CFGF_NODEFAULT),
        CFG_STR("args", 0, CFGF_NODEFAULT),
        CFG_STR("pre", 0, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opts[] = {
        CFG_SEC("process", process_opts, CFGF_MULTI | CFGF_TITLE),
        CFG_INT("frequency", 10, CFGF_NONE),
        CFG_END()
    };

    cfg_t *cfg = cfg_init(opts, CFGF_NONE);
    //cfg_set_validate_func(cfg, "bookmark|port", conf_validate_port);
    //cfg_set_validate_func(cfg, "bookmark", conf_validate_bookmark);

    switch(cfg_parse(cfg, filename))
    {
        case CFG_FILE_ERROR:
            printf("warning: configuration file '%s' could not be read: %s\n",
                    filename, strerror(errno));
            printf("continuing with default values...\n\n");
        case CFG_SUCCESS:
            break;
        case CFG_PARSE_ERROR:
            return 0;
    }

    return cfg;
}

char* getline_(FILE *file)
{
    int line_len = 64;
    char *line_ptr = NULL; 
    if (file == NULL)
        return NULL;

    line_ptr = malloc(sizeof(char) * line_len);
    if (line_ptr != NULL)
    {
        int c = EOF;
        unsigned int i = 0;
        while ( (c=getc(file))!='\n' && c!=EOF )
        {
            if (i > line_len-1)
            {
                line_len = line_len << 1;
                line_ptr = realloc(line_ptr, sizeof(char)*line_len);
            }
            line_ptr[i++] = (char) c;
        }

        if (i==0 && c==EOF)
        {
            free(line_ptr);
            line_ptr = NULL;
        }
        else
        {
            if (i > line_len-1)
            {
                line_len += 1;
                line_ptr = realloc(line_ptr, sizeof(char)*line_len);
            }
            //else 
            //{
            //    line_ptr = realloc(line_ptr, sizeof(char)*(i+1));
            //}
            line_ptr[i] = '\0';
        }
    }

    return line_ptr;
}

int parse_file(char*** dst, int* size, const char* filename)
{
    FILE *file = NULL;
    int i = 0;
    char *p = NULL;

    if (filename == NULL || dst==NULL || size==NULL)
        return 1;

    file = fopen(filename, "r");
    if (file == NULL)
        return 1;
    
    *size = 4;
    *dst = (char **) malloc(sizeof(char*) * (*size)); 
    while ( (p = getline_(file)) != NULL )
    {
        if (i > *size - 1)
        { 
           *size = *size << 1;
           *dst = (char **) realloc(*dst, *size * sizeof(char*));
        }
        (*dst)[i++] = p;   
    }
    
    if (i==0)
    {
       free(*dst);
       *dst = NULL;
       *size = 0;
    }   
    else
    {
       *size = i; 
    }
    
    fclose(file);

    return 0;
}

int parse_ps(char*** dst, int* size, const char* comm)
{
    const char *ps_cmd_head = "ps -o pid= -o args= -C ";
    const char *ps_cmd_end = " > tmp";
    int ps_cmd_head_len = strlen(ps_cmd_head);
    int ps_cmd_end_len = strlen(ps_cmd_end);
    int comm_len = 0;
    char *buf = NULL;
    char *p = NULL;
    int status = -1;

    if (comm == NULL)
        return 1;

    comm_len = strlen(comm);
    if (comm_len == 0)
        return 1;

    buf = (char*)malloc(sizeof(char) * (ps_cmd_head_len + comm_len + ps_cmd_end_len + 1));
    p = buf;
    memcpy(p, ps_cmd_head, ps_cmd_head_len);
    p += ps_cmd_head_len;
    memcpy(p, comm, comm_len);
    p += comm_len;
    memcpy(p, ps_cmd_end, ps_cmd_end_len);
    p += ps_cmd_end_len;
    memset(p, 0, 1); 
    
    //printf("buf==%s\n", buf);
    status = system(buf);
    if (status == 0)
    {
        status = parse_file(dst, size, "tmp");
    }

    if (buf != NULL)
    {
        free(buf);
        buf = NULL;
    }

    return status;
}

tree_node_t* make_node(ps_t* data, char* node_name)
{
    tree_node_t *node = malloc(sizeof(tree_node_t));
    node->node_name = node_name;
    node->data = data;
    node->first_child = NULL;
    node->next_sibling = NULL;
    return node;
}

int free_node(tree_node_t* node)
{
    if (node != NULL)
    {
         free(node->node_name);
         if (node->data != NULL) 
         {
             if (node->data->ps_conf != NULL)
             {
                  free(node->data->ps_conf->comm);
                  free(node->data->ps_conf->args);
                  free(node->data->ps_conf);
             } 
             free(node->data);
         }  
         free(node);
    }
}

#define assert_tree_node(node) (node != NULL && node->data != NULL && node->data->ps_conf != NULL && node->data->ps_conf->comm != NULL && node->data->ps_conf->args != NULL)

typedef int (*f_tree_handler) (tree_node_t * node);
void handle_tree_left_seq(tree_node_t *tree, f_tree_handler p_fun)
{
    if (tree == NULL || p_fun == NULL)
        return;
    
    if (tree->first_child != NULL)
    {
        handle_tree_left_seq(tree->first_child, p_fun);
    } 
    (*p_fun)(tree);
    if (tree->next_sibling != NULL)
    {
        handle_tree_left_seq(tree->next_sibling, p_fun);
    }
}

void handle_tree_middle_seq(tree_node_t *tree, f_tree_handler p_fun)
{
    if (tree == NULL || p_fun == NULL)
        return;
    
    (*p_fun)(tree);
    if (tree->first_child != NULL)
    {
        handle_tree_middle_seq(tree->first_child, p_fun);
    } 
    if (tree->next_sibling != NULL)
    {
        handle_tree_middle_seq(tree->next_sibling, p_fun);
    }
}

tree_node_t* find_node(tree_node_t* tree, const char* node_name)
{
    tree_node_t *node = NULL;
    if (tree == NULL || node_name == NULL)
        return NULL;

    if (tree->node_name!=NULL && strcmp(tree->node_name, node_name)==0)
    {
        node = tree;
    }
    if (node==NULL && tree->first_child!=NULL)
    {
        node = find_node(tree->first_child, node_name);
    }
    if (node==NULL && tree->next_sibling!=NULL)
    {
        node = find_node(tree->next_sibling, node_name);
    }

    return node;
}

void insert_node(tree_node_t* node, char* pre_node_name)
{
    tree_node_t *pre_node = NULL;
    if (node == NULL)
        return;
    
    if (pre_node_name == NULL)
    {
        pre_node = g_tree_ps;
    }
    else
    {
        pre_node = find_node(g_tree_ps, pre_node_name);
    }
    if (pre_node == NULL)
    {
        pre_node = make_node(NULL, pre_node_name);
        insert_node(pre_node, NULL);
    } 
    
    if (pre_node->first_child == NULL)
    {
        pre_node->first_child = node;
    }
    else
    {
        tree_node_t *p = node;
        while (p != NULL)
        {
            tree_node_t *p_next = p->next_sibling;
            p->next_sibling = pre_node->first_child->next_sibling;
            pre_node->first_child->next_sibling = p; 
            p = p_next;
        }
    }
}


void adjust_node(tree_node_t* node, char* pre_node_name)
{
    tree_node_t *pre_node = NULL;
    if (node == NULL)
        return;

    if (pre_node_name == NULL)
    {
        pre_node = g_tree_ps;
        return;
    } 

    pre_node = find_node(g_tree_ps, pre_node_name);
    if (pre_node == NULL)
    {
        pre_node = make_node(NULL, pre_node_name);
        insert_node(pre_node, NULL);
    }
    if (node == g_tree_ps->first_child) 
    {
        g_tree_ps->first_child = node->next_sibling;
        node->next_sibling = NULL;
    }
    else
    {
        tree_node_t *p = g_tree_ps->first_child;
        while (p != NULL)
        {
            if (p->next_sibling == node)
            {
                p->next_sibling = node->next_sibling;
                node->next_sibling = NULL;
                break;
            }
            p = p->next_sibling;
        }   
    }

    if (pre_node->first_child == NULL)
    {
        pre_node->first_child = node;
    }
    else
    {
        tree_node_t *p = node;
        while (p != NULL)
        {
            tree_node_t *p_next = p->next_sibling;
            p->next_sibling = pre_node->first_child->next_sibling;
            pre_node->first_child->next_sibling = p; 
            p = p_next;
        }
    }
}

void init()
{
    // read config, and init pid, if any process is not up, start it.
    int i = 0;

    cfg_t *cfg = parse_conf("config.conf");
    if (cfg == NULL)
    {
        return;
    }

    g_frequency = cfg_getint(cfg, "frequency");

    g_tree_ps = make_node(NULL, NULL); 

    for (i=0; i<cfg_size(cfg, "process"); i++)
    {
        tree_node_t *node = NULL; 
        cfg_t *ps_opt = cfg_getnsec(cfg, "process", i);
        ps_conf_t *ps_conf = (ps_conf_t*)malloc(sizeof(ps_conf_t));
        ps_conf->comm = strdup(cfg_getstr(ps_opt, "comm"));
        ps_conf->args = strdup(cfg_getstr(ps_opt, "args"));
        ps_t *ps = (ps_t*)malloc(sizeof(ps_t));
        ps->pid = PID_UNDEFINED;
        ps->ps_conf = ps_conf;
        node = find_node(g_tree_ps, ps_opt->title);
        if (node != NULL)
        {
            node->data = ps;
            // re-layout
            adjust_node(node, strdup(cfg_getstr(ps_opt, "pre"))); 
        }
        else
        {
            char *pre = cfg_getstr(ps_opt, "pre");
            node = make_node(ps, ps_opt->title==NULL?NULL:strdup(ps_opt->title));
            insert_node(node, pre!=NULL ? strdup(pre) : NULL );
        }
     }

    cfg_free(cfg);
}

int fresh_node_data(tree_node_t* node)
{
    int size = 0;
    char **content = NULL;
    char *pos = NULL;
    char *end = NULL;
    int j = 0;
    if (!assert_tree_node(node))
        return 1;

    node->data->pid = PID_UNDEFINED;
    if (0 != parse_ps(&content, &size, node->data->ps_conf->comm))
        return 1;

    for (j=0; j<size; j++)
    {
      if (isspace(*content[j]))
      	  pos = strchr(content[j]+1, ' ');
      else
          pos = strchr(content[j], ' ');
      
      if (pos!=NULL && node->data->ps_conf->args!=NULL)
      {
          char *p = node->data->ps_conf->args + strlen(node->data->ps_conf->args) - 1;
          while(p>node->data->ps_conf->args && (*p=='&' || isspace(*p)))
          {
              p--;
          }
          if (strncmp(pos+1, node->data->ps_conf->args, p+1-node->data->ps_conf->args)==0) 
          {
              char *pid = strndup(content[j], pos-content[j]);
              node->data->pid = atoi(pid);
              free(pid);
          }
      }
    }
    free_array(content, size);
    free(content);
    return 0;
}

void pre_guard()
{
    int i = 0;
    int size = 0;
    char **content = NULL;
    if (g_tree_ps == NULL) 
	return;
    // use call back function to do.  
    handle_tree_left_seq(g_tree_ps->first_child, &fresh_node_data);     
}

void free_mem()
{
    handle_tree_left_seq(g_tree_ps, &free_node);     
}

int kill(tree_node_t* node)
{
    char buf[32] = "kill -9 ";
    char tmp[32] = {0}; 
    if (node == NULL ||
        node->data == NULL ||
        node->data->pid == PID_UNDEFINED ||
        node->data->ps_conf == NULL)
        return 1;

    sprintf(buf, "kill -9 %u", node->data->pid);
    printf("kill %s\n", node->data->ps_conf->args);
    return system(buf);
}

int exec(tree_node_t* node)
{
    if (node == NULL ||
        node->data == NULL ||
        node->data->ps_conf == NULL ||
        node->data->ps_conf->comm == NULL)
        return 1;

    printf("exec %s\n", node->data->ps_conf->args);
    return system(node->data->ps_conf->args); 
}

void kill_all(tree_node_t* tree)
{
    if (tree == NULL)
        return;
    
    handle_tree_middle_seq(tree, &kill);
}

void start_all(tree_node_t* tree)
{
    if (tree == NULL)
        return;

    handle_tree_middle_seq(tree, &exec);
}

void start_self(tree_node_t* tree)
{
    if (tree == NULL)
        return;
    
    exec(tree);
}

void check(tree_node_t *tree)
{
    if (tree == NULL)
        return;
    
    if(tree->data->pid == PID_UNDEFINED)
    {
	if (tree->first_child != NULL)
	{	
            kill_all(tree->first_child);
	}
        start_self(tree);
	if (tree->first_child != NULL)
	{	
            start_all(tree->first_child);
	}
    } 
    else 
    {
        if (tree->first_child != NULL)
        {
            check(tree->first_child);
        } 
    }

    if (tree->next_sibling != NULL)
    {
        check(tree->next_sibling);
    }
}

void guard()
{
    check(g_tree_ps->first_child);
}

int main(int argc, char** argv)
{
   init();
   while (1)
   {
       pre_guard();
       guard();
       sleep(g_frequency);
   }

   free_mem();
   
   return 0;
}
