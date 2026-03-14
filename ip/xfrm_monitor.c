/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C)2005 USAGI/WIDE Project
 *
 * based on ipmonitor.c
 *
 * Authors:
 *	Masahide NAKAMURA @USAGI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "utils.h"
#include "xfrm.h"
#include "ip_common.h"

static void usage(void) __attribute__((noreturn));
static int listen_all_nsid;
static bool nokeys;

static void usage(void)
{
	fprintf(stderr,
		"Usage: ip xfrm monitor [ nokeys ] [ all-nsid ] [ all | OBJECTS | help ]\n"
		"OBJECTS := { acquire | expire | SA | aevent | policy | report }\n");
	exit(-1);
}

static int xfrm_acquire_print(struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct xfrm_user_acquire *xacq = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[XFRMA_MAX+1];
	__u16 family;

	len -= NLMSG_LENGTH(sizeof(*xacq));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	parse_rtattr(tb, XFRMA_MAX, XFRMACQ_RTA(xacq), len);

	family = xacq->sel.family;
	if (family == AF_UNSPEC)
		family = xacq->policy.sel.family;
	if (family == AF_UNSPEC)
		family = preferred_family;

	fprintf(fp, "acquire ");

	fprintf(fp, "proto %s ", strxf_xfrmproto(xacq->id.proto));
	if (show_stats > 0 || xacq->id.spi) {
		__u32 spi = ntohl(xacq->id.spi);

		fprintf(fp, "spi 0x%08x", spi);
		if (show_stats > 0)
			fprintf(fp, "(%u)", spi);
		fprintf(fp, " ");
	}
	fprintf(fp, "%s", _SL_);

	xfrm_selector_print(&xacq->sel, family, fp, "  sel ");

	xfrm_policy_info_print(&xacq->policy, tb, fp, "    ", "  policy ");

	if (show_stats > 0)
		fprintf(fp, "  seq 0x%08u ", xacq->seq);
	if (show_stats > 0) {
		fprintf(fp, "%s-mask %s ",
			strxf_algotype(XFRMA_ALG_CRYPT),
			strxf_mask32(xacq->ealgos));
		fprintf(fp, "%s-mask %s ",
			strxf_algotype(XFRMA_ALG_AUTH),
			strxf_mask32(xacq->aalgos));
		fprintf(fp, "%s-mask %s",
			strxf_algotype(XFRMA_ALG_COMP),
			strxf_mask32(xacq->calgos));
	}
	fprintf(fp, "%s", _SL_);

	if (oneline)
		fprintf(fp, "\n");
	fflush(fp);

	return 0;
}

static int xfrm_state_flush_print(struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct xfrm_usersa_flush *xsf = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	const char *str;

	len -= NLMSG_SPACE(sizeof(*xsf));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	fprintf(fp, "Flushed state ");

	str = strxf_xfrmproto(xsf->proto);
	if (str)
		fprintf(fp, "proto %s", str);
	else
		fprintf(fp, "proto %u", xsf->proto);
	fprintf(fp, "%s", _SL_);

	if (oneline)
		fprintf(fp, "\n");
	fflush(fp);

	return 0;
}

static int xfrm_policy_flush_print(struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[XFRMA_MAX+1];
	FILE *fp = (FILE *)arg;
	int len = n->nlmsg_len;

	len -= NLMSG_SPACE(0);
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	fprintf(fp, "Flushed policy ");

	parse_rtattr(tb, XFRMA_MAX, NLMSG_DATA(n), len);

	if (tb[XFRMA_POLICY_TYPE]) {
		struct xfrm_userpolicy_type *upt;

		fprintf(fp, "ptype ");

		if (RTA_PAYLOAD(tb[XFRMA_POLICY_TYPE]) < sizeof(*upt))
			fprintf(fp, "(ERROR truncated)");

		upt = RTA_DATA(tb[XFRMA_POLICY_TYPE]);
		fprintf(fp, "%s ", strxf_ptype(upt->type));
	}

	fprintf(fp, "%s", _SL_);

	if (oneline)
		fprintf(fp, "\n");
	fflush(fp);

	return 0;
}

static int xfrm_report_print(struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct xfrm_user_report *xrep = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[XFRMA_MAX+1];
	__u16 family;

	len -= NLMSG_LENGTH(sizeof(*xrep));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	family = xrep->sel.family;
	if (family == AF_UNSPEC)
		family = preferred_family;

	fprintf(fp, "report ");

	fprintf(fp, "proto %s ", strxf_xfrmproto(xrep->proto));
	fprintf(fp, "%s", _SL_);

	xfrm_selector_print(&xrep->sel, family, fp, "  sel ");

	parse_rtattr(tb, XFRMA_MAX, XFRMREP_RTA(xrep), len);

	xfrm_xfrma_print(tb, family, fp, "  ", nokeys, true);

	if (oneline)
		fprintf(fp, "\n");

	return 0;
}

static void xfrm_ae_flags_print(__u32 flags, void *arg)
{
	FILE *fp = (FILE *)arg;

	fprintf(fp, " (0x%x) ", flags);
	if (!flags)
		return;
	if (flags & XFRM_AE_CR)
		fprintf(fp, " replay update ");
	if (flags & XFRM_AE_CE)
		fprintf(fp, " timer expired ");
	if (flags & XFRM_AE_CU)
		fprintf(fp, " policy updated ");

}

static void xfrm_usersa_print(const struct xfrm_usersa_id *sa_id, __u32 reqid, FILE *fp)
{
	fprintf(fp, "dst %s ",
		rt_addr_n2a(sa_id->family, sizeof(sa_id->daddr), &sa_id->daddr));

	fprintf(fp, " reqid 0x%x", reqid);

	fprintf(fp, " protocol %s ", strxf_proto(sa_id->proto));
	fprintf(fp, " SPI 0x%x", ntohl(sa_id->spi));
}

static int xfrm_ae_print(struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct xfrm_aevent_id *id = NLMSG_DATA(n);

	fprintf(fp, "Async event ");
	xfrm_ae_flags_print(id->flags, arg);
	fprintf(fp, "\n\t");
	fprintf(fp, "src %s ", rt_addr_n2a(id->sa_id.family,
					   sizeof(id->saddr), &id->saddr));

	xfrm_usersa_print(&id->sa_id, id->reqid, fp);

	fprintf(fp, "\n");
	fflush(fp);

	return 0;
}

static void xfrm_print_addr(FILE *fp, int family, xfrm_address_t *a)
{
	fprintf(fp, "%s", rt_addr_n2a(family, sizeof(*a), a));
}

static int xfrm_mapping_print(struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct xfrm_user_mapping *map = NLMSG_DATA(n);

	fprintf(fp, "Mapping change ");
	xfrm_print_addr(fp, map->id.family, &map->old_saddr);

	fprintf(fp, ":%d -> ", ntohs(map->old_sport));
	xfrm_print_addr(fp, map->id.family, &map->new_saddr);
	fprintf(fp, ":%d\n\t", ntohs(map->new_sport));

	xfrm_usersa_print(&map->id, map->reqid, fp);

	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

static void xfrm_migrate_encap_print(struct rtattr *tb[], __u16 family,
				     const char *prefix, FILE *fp)
{
	struct xfrm_encap_tmpl *e = RTA_DATA(tb[XFRMA_ENCAP]);
	static const xfrm_address_t zero_addr;

	if (prefix)
		fputs(prefix, fp);
	if (e->encap_type == 0) {
		fprintf(fp, "encap none ");
	} else {
		fprintf(fp, "encap espinudp sport %u dport %u ",
			ntohs(e->encap_sport), ntohs(e->encap_dport));
		if (memcmp(&e->encap_oa, &zero_addr, sizeof(zero_addr)))
			fprintf(fp, "addr %s ",
				rt_addr_n2a(family, sizeof(e->encap_oa),
					    &e->encap_oa));
	}
	if (prefix)
		fprintf(fp, "%s", _SL_);
}

static void xfrm_migrate_offload_print(struct rtattr *tb[],
				       const char *prefix, FILE *fp)
{
	struct xfrm_user_offload *xuo = RTA_DATA(tb[XFRMA_OFFLOAD_DEV]);

	if (prefix)
		fputs(prefix, fp);
	if (xuo->ifindex == 0)
		fprintf(fp, "offload none ");
	else
		fprintf(fp, "offload dev %s dir %s ",
			ll_index_to_name(xuo->ifindex),
			(xuo->flags & XFRM_OFFLOAD_INBOUND) ? "in" : "out");
	if (prefix)
		fprintf(fp, "%s", _SL_);
}

static void xfrm_migrate_mode_print(__u8 mode, FILE *fp)
{
	switch (mode) {
	case XFRM_MODE_TRANSPORT:
		fprintf(fp, "transport");
		break;
	case XFRM_MODE_TUNNEL:
		fprintf(fp, "tunnel");
		break;
	case XFRM_MODE_BEET:
		fprintf(fp, "beet");
		break;
	case XFRM_MODE_IPTFS:
		fprintf(fp, "iptfs");
		break;
	default:
		fprintf(fp, "%u", mode);
		break;
	}
}

static void xfrm_migrate_one_print(const struct xfrm_user_migrate *um,
				   FILE *fp)
{
	fprintf(fp, "    proto %s mode ", strxf_proto(um->proto));
	xfrm_migrate_mode_print(um->mode, fp);
	fprintf(fp, " reqid %u\n", um->reqid);

	fprintf(fp, "    old src %s",
		rt_addr_n2a(um->old_family, sizeof(um->old_saddr),
			    &um->old_saddr));
	fprintf(fp, " dst %s\n",
		rt_addr_n2a(um->old_family, sizeof(um->old_daddr),
			    &um->old_daddr));

	fprintf(fp, "    new src %s",
		rt_addr_n2a(um->new_family, sizeof(um->new_saddr),
			    &um->new_saddr));
	fprintf(fp, " dst %s\n",
		rt_addr_n2a(um->new_family, sizeof(um->new_daddr),
			    &um->new_daddr));
	fprintf(fp, "\n");
}

static int xfrm_migrate_print(struct nlmsghdr *n, void *arg)
{
	struct xfrm_userpolicy_id *xpid = NLMSG_DATA(n);
	struct rtattr *tb[XFRMA_MAX+1];
	struct rtattr *rta_m;
	struct rtattr *rta;
	FILE *fp = (FILE *)arg;
	int len = n->nlmsg_len - NLMSG_SPACE(sizeof(*xpid));
	int rem;

	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}
	rta = XFRMPID_RTA(xpid);
	parse_rtattr(tb, XFRMA_MAX, rta, len);

	fprintf(fp, "Migrated dir ");
	switch (xpid->dir) {
	case XFRM_POLICY_IN:
		fprintf(fp, "in");
		break;
	case XFRM_POLICY_OUT:
		fprintf(fp, "out");
		break;
	case XFRM_POLICY_FWD:
		fprintf(fp, "fwd");
		break;
	default:
		fprintf(fp, "%u", xpid->dir);
		break;
	}
	if (tb[XFRMA_POLICY_TYPE]) {
		struct xfrm_userpolicy_type *upt = RTA_DATA(tb[XFRMA_POLICY_TYPE]);

		fprintf(fp, " type %s", strxf_ptype(upt->type));
	}
	fprintf(fp, " ");
	xfrm_selector_print(&xpid->sel, preferred_family, fp, NULL);

	if (tb[XFRMA_ENCAP])
		xfrm_migrate_encap_print(tb, xpid->sel.family, NULL, fp);
	if (tb[XFRMA_OFFLOAD_DEV])
		xfrm_migrate_offload_print(tb, NULL, fp);
	if (tb[XFRMA_ENCAP] || tb[XFRMA_OFFLOAD_DEV])
		fprintf(fp, "\n");

	if (tb[XFRMA_KMADDRESS]) {
		struct xfrm_user_kmaddress *k = RTA_DATA(tb[XFRMA_KMADDRESS]);

		fprintf(fp, "  kmaddress local %s",
			rt_addr_n2a(k->family, sizeof(k->local), &k->local));
		fprintf(fp, " remote %s\n",
			rt_addr_n2a(k->family, sizeof(k->remote), &k->remote));
	}

	/* XFRMA_MIGRATE appears once per SA; iterate manually */
	rem = len;
	for (rta_m = rta; RTA_OK(rta_m, rem); rta_m = RTA_NEXT(rta_m, rem)) {
		if (rta_m->rta_type == XFRMA_MIGRATE &&
		    RTA_PAYLOAD(rta_m) >= sizeof(struct xfrm_user_migrate))
			xfrm_migrate_one_print(RTA_DATA(rta_m), fp);
	}

	if (oneline)
		fprintf(fp, "\n");
	fflush(fp);

	return 0;
}

static int xfrm_migrate_state_print(struct nlmsghdr *n, void *arg)
{
	struct rtattr *rta;
	FILE *fp = (FILE *)arg;
	struct rtattr *tb[XFRMA_MAX+1];
	struct xfrm_user_migrate_state *xums = NLMSG_DATA(n);
	int len = n->nlmsg_len - NLMSG_SPACE(sizeof(*xums));

	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	rta = XFRMUMS_RTA(xums);
	parse_rtattr(tb, XFRMA_MAX, rta, len);

	fprintf(fp, "Migrated state ");

	if (tb[XFRMA_SA_DIR]) {
		__u8 dir = rta_getattr_u8(tb[XFRMA_SA_DIR]);

		if (dir == XFRM_SA_DIR_IN)
			fprintf(fp, "dir in ");
		else if (dir == XFRM_SA_DIR_OUT)
			fprintf(fp, "dir out ");
		else
			fprintf(fp, "dir %u ", dir);
	}

	fprintf(fp, "proto %s ", strxf_xfrmproto(xums->id.proto));
	fprintf(fp, "spi 0x%08x ", ntohl(xums->id.spi));
	fprintf(fp, "dst %s ",
		rt_addr_n2a(xums->id.family, sizeof(xums->id.daddr),
			    &xums->id.daddr));

	if (xums->old_mark.v || xums->old_mark.m)
		fprintf(fp, "mark 0x%x/0x%x ", xums->old_mark.v,
			xums->old_mark.m);

	fprintf(fp, "\n new-dst %s ",
		rt_addr_n2a(xums->new_family, sizeof(xums->new_daddr),
			    &xums->new_daddr));
	fprintf(fp, "new-src %s ",
		rt_addr_n2a(xums->new_family, sizeof(xums->new_saddr),
			    &xums->new_saddr));
	fprintf(fp, "new-reqid %u", xums->new_reqid);

	if (tb[XFRMA_MARK] || tb[XFRMA_SET_MARK]) {
		fprintf(fp, "\n ");
		if (tb[XFRMA_MARK]) {
			struct xfrm_mark *m = RTA_DATA(tb[XFRMA_MARK]);

			fprintf(fp, "new-mark 0x%x/0x%x ", m->v, m->m);
		}

		if (tb[XFRMA_SET_MARK]) {
			__u32 smark = rta_getattr_u32(tb[XFRMA_SET_MARK]);
			__u32 smask = tb[XFRMA_SET_MARK_MASK] ?
				rta_getattr_u32(tb[XFRMA_SET_MARK_MASK]) : 0xffffffff;

			fprintf(fp, "set-mark 0x%x/0x%x ", smark, smask);
		}
	}

	if (tb[XFRMA_ENCAP]) {
		fprintf(fp, "\n ");
		xfrm_migrate_encap_print(tb, xums->new_family, NULL, fp);
	}

	if (tb[XFRMA_OFFLOAD_DEV]) {
		fprintf(fp, "\n ");
		xfrm_migrate_offload_print(tb, NULL, fp);
	} else if (xums->flags & XFRM_MIGRATE_STATE_NO_OFFLOAD) {
		fprintf(fp, "\n no-offload ");
	}

	if (tb[XFRMA_MTIMER_THRESH] || tb[XFRMA_NAT_KEEPALIVE_INTERVAL]) {
		fprintf(fp, "\n ");
		if (tb[XFRMA_MTIMER_THRESH])
			fprintf(fp, "mtimer-thresh %u ",
				rta_getattr_u32(tb[XFRMA_MTIMER_THRESH]));
		if (tb[XFRMA_NAT_KEEPALIVE_INTERVAL])
			fprintf(fp, "nat-keepalive %u ",
				rta_getattr_u32(tb[XFRMA_NAT_KEEPALIVE_INTERVAL]));
	}

	fprintf(fp, "%s", _SL_);
	if (oneline)
		fprintf(fp, "\n");
	fflush(fp);

	return 0;
}

static int xfrm_accept_msg(struct rtnl_ctrl_data *ctrl,
			   struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;

	if (timestamp)
		print_timestamp(fp);

	if (listen_all_nsid) {
		if (ctrl == NULL || ctrl->nsid < 0)
			fprintf(fp, "[nsid current]");
		else
			fprintf(fp, "[nsid %d]", ctrl->nsid);
	}

	switch (n->nlmsg_type) {
	case XFRM_MSG_NEWSA:
	case XFRM_MSG_DELSA:
	case XFRM_MSG_UPDSA:
	case XFRM_MSG_EXPIRE:
		xfrm_state_print(n, arg);
		return 0;
	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_DELPOLICY:
	case XFRM_MSG_UPDPOLICY:
	case XFRM_MSG_POLEXPIRE:
		xfrm_policy_print(n, arg);
		return 0;
	case XFRM_MSG_ACQUIRE:
		xfrm_acquire_print(n, arg);
		return 0;
	case XFRM_MSG_FLUSHSA:
		xfrm_state_flush_print(n, arg);
		return 0;
	case XFRM_MSG_FLUSHPOLICY:
		xfrm_policy_flush_print(n, arg);
		return 0;
	case XFRM_MSG_REPORT:
		xfrm_report_print(n, arg);
		return 0;
	case XFRM_MSG_NEWAE:
		xfrm_ae_print(n, arg);
		return 0;
	case XFRM_MSG_MAPPING:
		xfrm_mapping_print(n, arg);
		return 0;
	case XFRM_MSG_GETDEFAULT:
		xfrm_policy_default_print(n, arg);
		return 0;
	case XFRM_MSG_MIGRATE:
		xfrm_migrate_print(n, arg);
		return 0;
	case XFRM_MSG_MIGRATE_STATE:
		xfrm_migrate_state_print(n, arg);
		return 0;
	default:
		break;
	}

	if (n->nlmsg_type != NLMSG_ERROR && n->nlmsg_type != NLMSG_NOOP &&
	    n->nlmsg_type != NLMSG_DONE) {
		fprintf(fp, "Unknown message: %08d 0x%08x 0x%08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
	}
	return 0;
}

extern struct rtnl_handle rth;

int do_xfrm_monitor(int argc, char **argv)
{
	char *file = NULL;
	unsigned int groups = ~((unsigned)0); /* XXX */
	int lacquire = 0;
	int lexpire = 0;
	int laevent = 0;
	int lpolicy = 0;
	int lsa = 0;
	int lreport = 0;

	rtnl_close(&rth);

	while (argc > 0) {
		if (matches(*argv, "file") == 0) {
			NEXT_ARG();
			file = *argv;
		} else if (strcmp(*argv, "nokeys") == 0) {
			nokeys = true;
		} else if (strcmp(*argv, "all") == 0) {
			/* fall out */
		} else if (matches(*argv, "all-nsid") == 0) {
			listen_all_nsid = 1;
		} else if (matches(*argv, "acquire") == 0) {
			lacquire = 1;
			groups = 0;
		} else if (matches(*argv, "expire") == 0) {
			lexpire = 1;
			groups = 0;
		} else if (matches(*argv, "SA") == 0) {
			lsa = 1;
			groups = 0;
		} else if (matches(*argv, "aevent") == 0) {
			laevent = 1;
			groups = 0;
		} else if (matches(*argv, "policy") == 0) {
			lpolicy = 1;
			groups = 0;
		} else if (matches(*argv, "report") == 0) {
			lreport = 1;
			groups = 0;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			fprintf(stderr, "Argument \"%s\" is unknown, try \"ip xfrm monitor help\".\n", *argv);
			exit(-1);
		}
		argc--;	argv++;
	}

	if (lacquire)
		groups |= nl_mgrp(XFRMNLGRP_ACQUIRE);
	if (lexpire)
		groups |= nl_mgrp(XFRMNLGRP_EXPIRE);
	if (lsa)
		groups |= nl_mgrp(XFRMNLGRP_SA);
	if (lpolicy)
		groups |= nl_mgrp(XFRMNLGRP_POLICY);
	if (laevent)
		groups |= nl_mgrp(XFRMNLGRP_AEVENTS);
	if (lreport)
		groups |= nl_mgrp(XFRMNLGRP_REPORT);

	if (file) {
		FILE *fp;
		int err;

		fp = fopen(file, "r");
		if (fp == NULL) {
			perror("Cannot fopen");
			exit(-1);
		}
		err = rtnl_from_file(fp, xfrm_accept_msg, stdout);
		fclose(fp);
		return err;
	}

	if (rtnl_open_byproto(&rth, groups, NETLINK_XFRM) < 0)
		exit(1);
	if (listen_all_nsid && rtnl_listen_all_nsid(&rth) < 0)
		exit(1);

	if (rtnl_listen(&rth, xfrm_accept_msg, (void *)stdout) < 0)
		exit(2);

	return 0;
}
