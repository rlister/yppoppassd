/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include <rpc/types.h>
#include <rpc/xdr.h>

#include "yppasswd.h"
#ifndef lint
/*static char sccsid[] = "from: @(#)yppasswd.x 1.1 87/04/13 Copyr 1987 Sun Micro";*/
/*static char sccsid[] = "from: @(#)yppasswd.x	2.1 88/08/01 4.0 RPCSRC";*/
static char rcsid[] = "yppasswd.x,v 1.1.1.1 1995/02/18 05:34:09 hjl Exp";
#endif /* not lint */

bool_t
xdr_x_passwd(XDR *xdrs, x_passwd *objp)
{

	 register long *buf;

	 if (!xdr_string(xdrs, &objp->pw_name, ~0)) {
		 return (FALSE);
	 }
	 if (!xdr_string(xdrs, &objp->pw_passwd, ~0)) {
		 return (FALSE);
	 }
	 if (!xdr_int(xdrs, &objp->pw_uid)) {
		 return (FALSE);
	 }
	 if (!xdr_int(xdrs, &objp->pw_gid)) {
		 return (FALSE);
	 }
	 if (!xdr_string(xdrs, &objp->pw_gecos, ~0)) {
		 return (FALSE);
	 }
	 if (!xdr_string(xdrs, &objp->pw_dir, ~0)) {
		 return (FALSE);
	 }
	 if (!xdr_string(xdrs, &objp->pw_shell, ~0)) {
		 return (FALSE);
	 }
	return (TRUE);
}

bool_t
xdr_yppasswd(XDR *xdrs, yppasswd *objp)
{

	 register long *buf;

	 if (!xdr_string(xdrs, &objp->oldpass, ~0)) {
		 return (FALSE);
	 }
	 if (!xdr_x_passwd(xdrs, &objp->newpw)) {
		 return (FALSE);
	 }
	return (TRUE);
}
