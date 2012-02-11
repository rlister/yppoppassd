/* yppoppassd
 *
 * Copyright (c) 1997 Richard J Lister
 *
 * DESCRIPTION:
 *     This is a hack of the Linux yppasswd to support POP client password
 *     changes.
 *
 * NOTES:
 *     My Linux box (RedHat 4.0) doesn't have many of the man pages for
 *     RPC and YP functions. I got them off a Sun box.
 *     Many of the RPC calls have been replaced with new functions and
 *     should probably be changed here. See man pages. 
 *
 * CHANGE LOG:
 *
 *     $Log: yppoppassd.c,v $
 *     Revision 1.4  1997/05/28 19:57:27  ric
 *     Added more comments and cleaned up.
 *
 *     Revision 1.3  1997/05/28 19:27:20  ric
 *     Changed %s to %d for short passwd error message.
 *     Added revision[] string to initial hello.
 *
 *     Revision 1.2  1997/05/28 18:25:22  ric
 *     First fully working version. Added all RPC calls, and conversation with
 *     client.
 *
 *     Revision 1.1  1997/05/27 16:07:20  ric
 *     Initial revision
 *
 *
 *
 * Below is the copyright notice from yppasswd.c.
 *
 * Copyright (c) 1992/3 Theo de Raadt <deraadt@fsa.ca>
 * Modifications (c) 1994 Olaf Kirch <okir@monad.swb.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 */

static char rcsid[] = "$Id: yppoppassd.c,v 1.4 1997/05/28 19:57:27 ric Exp $";


#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <netdb.h>
#include <time.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#include "yppasswd.h"

static unsigned char itoa64[] =		/* 0 ... 63 => ascii - 64 */
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char *GetYPServer (void);
void WriteToClient (char *, ...);
void to64(char *, long int, int);
char *EnCrypt(char *);
int ChangePasswd (char *, struct passwd *pw, char *, char *);
void ReadFromClient (char *);

extern bool_t xdr_yppasswd(XDR *, yppasswd *);

char progname[] = "yppoppassd";
char revision[] = "$Revision: 1.4 $";

#define YPPASSWDPROG ((u_long)100009)
#define YPPASSWDVERS ((u_long)1)
#define YPPASSWDPROC_UPDATE ((u_long)1)

#define DEBUG printf
#define BUFSIZE 512
#define MIN_PASSWD_LENGTH 6


/* MAIN */
int
main (void) {
  char user[BUFSIZE] = "";
  char oldpass[BUFSIZE] = "";
  char newpass[BUFSIZE] = "";
  int newpass_len;
  char line[BUFSIZE];
  int status;
  struct passwd *pw;
  char *yp_master;

  /* open syslog here? */

  /* contact YP server */
  if ( (yp_master = GetYPServer() ) == NULL ) {
    WriteToClient("500 Can't contact YP server. Call sysadmin.");
    exit(1);
  }

  /* get username */
  WriteToClient("200 %s %s hello, who are you?", progname, revision);
  ReadFromClient(line);
  sscanf(line, "user %s", user);

  if ( strlen(user) == 0 ) {
    WriteToClient("500 Username required.");
    exit(1);
  }

  /* get information about user into a passwd struct
   * and test for existence of user */
  if ( (pw = getpwnam(user)) == NULL ) {
    WriteToClient("500 Can't find user named '%s'.", user);
    exit(1);
  }

  /* get old password */
  WriteToClient("200 your password please.");
  ReadFromClient(line);
  sscanf(line, "pass %s", oldpass);

  if ( strlen(oldpass) == 0 ) {
    WriteToClient("500 Password required.");
    exit(1);
  }

  /* Check old password is correct. Can't do if we're using shadow passwords. */
#ifndef SHADOWPWD
  if( strcmp(crypt(oldpass, pw->pw_passwd), pw->pw_passwd)) {
    WriteToClient("500 Old password is incorrect.");
    exit (1);
  }
#endif

                  
  /* get new password */
  WriteToClient("200 your new password please.");
  ReadFromClient(line);
  sscanf (line, "newpass %s", newpass);

  newpass_len = strlen(newpass);
  
  if ( newpass_len == 0 ) {
    WriteToClient("500 New password required.");
	  exit(1);
  }

  /* check new password is OK ... put any suitable function here that checks
   * the security of the password */
  if ( newpass_len < MIN_PASSWD_LENGTH ) {
    WriteToClient("500 New password must be at least %d characters long.",
                  MIN_PASSWD_LENGTH);
    exit(1);
  }

  /* Do actual call to rpc.yppasswdd to change password. */
  status = ChangePasswd(yp_master, pw, oldpass, newpass);

  /* got an error from the RPC call */
  if ( status ) {
    WriteToClient("500 rpc.yppasswdd error (status %s): password NOT changed.",
                  status);
    exit(1);
  }

  /* respond with success */
  WriteToClient("200 The password has been changed.");

  /* should get 'quit' from client */
  ReadFromClient(line);
  if ( strncmp(line, "quit", 4) ) {
    WriteToClient("500 Quit required.");
		exit (1);
  }

  /* terminate conversation politely */
  WriteToClient("200 Bye.");

  exit(status);
}


  

/* Reads a line from stdin up to \n or \r, terminates the string, and
 * downcases first word. */
void
ReadFromClient (char *line) {
	char *sp;
	int i;

	strcpy (line, "");
  
  /* grab data from stdin */
	fgets (line, BUFSIZE, stdin);

  /* get first occurences of \n and \r and null terminate string there */
	if ((sp = strchr(line, '\n')) != NULL) *sp = '\0'; 
	if ((sp = strchr(line, '\r')) != NULL) *sp = '\0'; 
	
	/* convert initial keyword on line to lower case. */
	for (sp = line; isalpha(*sp); sp++) *sp = tolower(*sp);
}





/* Do actual password change. This is a stripped-down
 * main() from yppasswd.c. */
int
ChangePasswd (char *yp_master, struct passwd *pw, char *oldpass, char *newpass) {
  struct yppasswd yppasswd;
  CLIENT *rpc_client;
  struct timeval rpc_timeout;
  int rpc_status;
  int rpc_error;
  char *error_string;


  /* create a yppasswd struct (see yppasswd.x) to send to RPC server */
  yppasswd.oldpass = strdup(oldpass);
  yppasswd.newpw.pw_passwd = EnCrypt(newpass);

  yppasswd.newpw.pw_name = pw->pw_name;
  yppasswd.newpw.pw_uid = pw->pw_uid;
  yppasswd.newpw.pw_gid = pw->pw_gid;
  yppasswd.newpw.pw_gecos = pw->pw_gecos;
  yppasswd.newpw.pw_dir = pw->pw_dir;
  yppasswd.newpw.pw_shell = pw->pw_shell;

  
  /* create RPC client, see clnt_create(3N) */
  rpc_client = clnt_create(yp_master, YPPASSWDPROG, YPPASSWDVERS, "udp" );

  /* Authentication. May not be required for Linux yppasswdd. */
  rpc_client->cl_auth = authunix_create_default();
  
  /* clean out the variable */
  bzero( (char*)&rpc_status, sizeof(rpc_status) );

  /* pick some sane timeout value */
  rpc_timeout.tv_sec = 25;
  rpc_timeout.tv_usec = 0;

  /* Do actual RPC call to server */
  rpc_error = clnt_call(rpc_client, YPPASSWDPROC_UPDATE,
                        xdr_yppasswd, (char*)&yppasswd,
                        xdr_int,      (char*)&rpc_status,
                        rpc_timeout );


  /* Get RPC errors */
  if ( rpc_error ) {
    error_string = strdup(clnt_sperrno(rpc_error));
    syslog(LOG_ERR, "RPC error: %s\n", error_string);
  }
  else if ( rpc_status ) {
    syslog(LOG_ERR, "Error while changing password, status = %d.", rpc_status);
  }

  /* tidy up RPC client */
  auth_destroy(rpc_client->cl_auth);
  clnt_destroy(rpc_client);

  return ((rpc_error || rpc_status) != 0);
}





/* Send a message to the POP client. This'll probably get put in
 * a dialog box for the user, so make it meaningful. */
void
WriteToClient (char *fmt, ...)
{
	va_list ap;
	
	va_start (ap, fmt);
	vfprintf (stdout, fmt, ap);
	fputs ("\r\n", stdout );
	fflush (stdout);
	va_end (ap);
}







/* Gets master YP server for this node's default domain, and checks
 * rpc.yppasswdd is running legally on master.
 * Returns name of YP master. */
char *
GetYPServer (void) {
  char *domainname;
  char *master;
  int error;
  int port;

  /* get node's default YP domain */
  if ( (error = yp_get_default_domain(&domainname)) ) {
    syslog(LOG_ERR, "%s: can't get local YP domain because %s",
           progname, yperr_string(error));
    return NULL;
  }

  /* get name of master server for passwd map */
  if ( (error = yp_master(domainname, "passwd.byname", &master)) ) {
    syslog(LOG_ERR, "%s: can't get name of master YP server because %s", 
           progname, yperr_string(error));
    return NULL;
  }

  /* open RPC port to master */
  /* NOTE: this should probably be replaced by rpcb_getaddr() ...
   * see getrpcport(3N) and rpcbind(3N). */
  port = getrpcport(master, YPPASSWDPROG, YPPASSWDPROC_UPDATE, IPPROTO_UDP);

  /* didn't return a port */
  if ( !port ) {
    syslog(LOG_ERR, "%s: can't contact rpc.yppasswdd on YP master.", progname);
    return NULL;
  }

  /* returned illegal port */
  if ( port >= IPPORT_RESERVED) {
    syslog(LOG_ERR, "%s: yppasswd daemon running on illegal port.", progname);
    return NULL;
  }

  return(master);
}




/* make encrypted password */
char *
EnCrypt (char *newpass) {
  char salt[9];

  /* grab a random printable character that isn't a colon */
  srandom((int)time((time_t *)NULL));
  to64(&salt[0], random(), 2);
  return strdup(crypt(newpass, salt));
}




/* needed by EnCrypt() */
void
to64(char *s, long int v, int n)
{
  while (--n >= 0)
    {
      *s++ = itoa64[v&0x3f];
      v >>= 6;
    }
}

