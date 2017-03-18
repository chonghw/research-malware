#include <gtk/gtk.h>

extern int quit;
extern unsigned short port;
extern unsigned long sip, dip;
extern unsigned short sport, dport;
extern char *comm;
extern char *args;
extern char plugin_dir[];
extern char trj_bin[], inst_dir[];
extern int spoof, results;
extern unsigned long spoofhost, resultshost;
extern unsigned short spoofport, resultsport;
extern int mod, rem;
extern char k1[], k2[];
unsigned int rsock;

void
on_window_destroy                      (GtkObject       *object,
                                        gpointer         user_data);

void
on_server_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_exit_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_clear_buffer_activate               (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_save_buffer_activate                (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_load_configs_activate               (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_save_configs_activate               (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_server_config_activate              (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_client_config_activate              (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_ok_button1_clicked                  (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_button1_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void
on_about_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_mod_spin_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_save_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_ok_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_button_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_save_client_button_clicked          (GtkButton       *button,
                                        gpointer         user_data);

void
on_ok_client_button_clicked          (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_client_button_clicked        (GtkButton       *button,
                                        gpointer         user_data);

void
on_save_client_button_clicked          (GtkButton       *button,
                                        gpointer         user_data);

void
on_load_client_button_clicked          (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_client_button_clicked        (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_client_button_clicked        (GtkButton       *button,
                                        gpointer         user_data);

void
on_send_button_clicked(GtkButton *button, gpointer user_data);

void
on_ctree_highlight(GtkCTree *tree, GtkCTreeNode *node);

void i_crypt(unsigned long, unsigned long, unsigned short, unsigned char *, unsigned char *, unsigned long);
void i_sha(char *, unsigned long, unsigned long *);
long i_strtol(char *, int, int);
void write_text(char *);
int ip_port_parse(char *, unsigned long *, unsigned short *);
unsigned short in_cksum(unsigned short *, int);
int load_client(char *);
int load_server(char *);
