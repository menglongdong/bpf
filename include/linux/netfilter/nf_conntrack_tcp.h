/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_CONNTRACK_TCP_H
#define _NF_CONNTRACK_TCP_H

#include <uapi/linux/netfilter/nf_conntrack_tcp.h>


struct ip_ct_tcp_state {
	/* 发送出去的最后一个字节，即当前已经发送出去的最大序列号 */
	u_int32_t	td_end;		/* max of seq + len */
	/* 
	 * 允许发送的最大的报文序列号，即对方的收包窗口的上限值。
	 * 这个是根据收到的ack号+window来确定的。
	 */
	u_int32_t	td_maxend;	/* max of ack + max(win, 1) */
	/* 本端的最大收包窗口大小。 */
	u_int32_t	td_maxwin;	/* max(win) */
	/* 作为发送端，发送出去的最大的ack号 */
	u_int32_t	td_maxack;	/* max of ack */
	/* 本端的窗口缩放因子 */
	u_int8_t	td_scale;	/* window scale factor */
	u_int8_t	flags;		/* per direction options */
};

struct ip_ct_tcp {
	struct ip_ct_tcp_state seen[2];	/* connection parameters per direction */
	u_int8_t	state;		/* state of the connection (enum tcp_conntrack) */
	/* For detecting stale connections */
	u_int8_t	last_dir;	/* Direction of the last packet (enum ip_conntrack_dir) */
	u_int8_t	retrans;	/* Number of retransmitted packets */
	u_int8_t	last_index;	/* Index of the last packet */
	u_int32_t	last_seq;	/* Last sequence number seen in dir */
	u_int32_t	last_ack;	/* Last sequence number seen in opposite dir */
	u_int32_t	last_end;	/* Last seq + len */
	u_int16_t	last_win;	/* Last window advertisement seen in dir */
	/* For SYN packets while we may be out-of-sync */
	u_int8_t	last_wscale;	/* Last window scaling factor seen */
	u_int8_t	last_flags;	/* Last flags set */
};

#endif /* _NF_CONNTRACK_TCP_H */
