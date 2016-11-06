/*
 * Author: Scott Campbell
 * header file
 *
 * see nersc.c for complete copyright information
 *
 */

int get_client_session_id();
void set_server_id(int,char*,int);
void s_audit(const char *, const char *, ...);
char* encode_string(const char *, const int len);
int set_interface_list();


