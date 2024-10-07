/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H


#include <linux/skbuff.h>
#include <linux/win_minmax.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>
#include <uapi/linux/tcp.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int __tcp_hdrlen(const struct tcphdr *th)
{
	return th->doff * 4;
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return __tcp_hdrlen(tcp_hdr(skb));
}

static inline struct tcphdr *inner_tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_inner_transport_header(skb);
}

static inline unsigned int inner_tcp_hdrlen(const struct sk_buff *skb)
{
	return inner_tcp_hdr(skb)->doff * 4;
}

/**
 * skb_tcp_all_headers - Returns size of all headers for a TCP packet
 * @skb: buffer
 *
 * Used in TX path, for a packet known to be a TCP one.
 *
 * if (skb_is_gso(skb)) {
 *         int hlen = skb_tcp_all_headers(skb);
 *         ...
 */
static inline int skb_tcp_all_headers(const struct sk_buff *skb)
{
	return skb_transport_offset(skb) + tcp_hdrlen(skb);
}

/**
 * skb_inner_tcp_all_headers - Returns size of all headers for an encap TCP packet
 * @skb: buffer
 *
 * Used in TX path, for a packet known to be a TCP one.
 *
 * if (skb_is_gso(skb) && skb->encapsulation) {
 *         int hlen = skb_inner_tcp_all_headers(skb);
 *         ...
 */
static inline int skb_inner_tcp_all_headers(const struct sk_buff *skb)
{
	return skb_inner_transport_offset(skb) + inner_tcp_hdrlen(skb);
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* TCP Fast Open */
#define TCP_FASTOPEN_COOKIE_MIN	4	/* Min Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_MAX	16	/* Max Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_SIZE 8	/* the size employed by this impl. */

/* TCP Fast Open Cookie as stored in memory */
struct tcp_fastopen_cookie {
	__le64	val[DIV_ROUND_UP(TCP_FASTOPEN_COOKIE_MAX, sizeof(u64))];
	s8	len;
	bool	exp;	/* In RFC6994 experimental option format */
};

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

/*These are used to set the sack_ok field in struct tcp_options_received */
#define TCP_SACK_SEEN     (1 << 0)   /*1 = peer is SACK capable, */
#define TCP_DSACK_SEEN    (1 << 2)   /*1 = DSACK was received from peer*/

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	int	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 3,	/* SACK seen on SYN packet		*/
		smc_ok : 1,	/* SMC seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
	u8	accecn:6,	/* AccECN index in header, 0=no options	*/
		saw_unknown:1,	/* Received unknown option		*/
		unused:1;
	u8	num_sacks;	/* Number of SACK blocks		*/
	/* 用户通过ioctl主动设定的MSS */
	u16	user_mss;	/* mss requested by user in ioctl	*/
	/* TCP三次握手期间协商出来的MSS */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

static inline void tcp_clear_options(struct tcp_options_received *rx_opt)
{
	rx_opt->tstamp_ok = rx_opt->sack_ok = 0;
	rx_opt->wscale_ok = rx_opt->snd_wscale = 0;
#if IS_ENABLED(CONFIG_SMC)
	rx_opt->smc_ok = 0;
#endif
}

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increase this, although since:
 *   size = TCPOLEN_SACK_BASE_ALIGNED (4) + n * TCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TCP header */
#define TCP_NUM_SACKS 4

struct tcp_request_sock_ops;

struct tcp_request_sock {
	struct inet_request_sock 	req;
	const struct tcp_request_sock_ops *af_specific;
	u64				snt_synack; /* first SYNACK sent time */
	bool				tfo_listener;
	bool				is_mptcp;
	bool				req_usec_ts;
#if IS_ENABLED(CONFIG_MPTCP)
	bool				drop_req;
#endif
	u32				txhash;
	u32				rcv_isn;
	u32				snt_isn;
	u32				ts_off;
	u32				snt_tsval_first;
	u32				snt_tsval_last;
	u32				last_oow_ack_time; /* last SYNACK */
	u32				rcv_nxt; /* the ack # by SYNACK. For
						  * FastOpen it's the seq#
						  * after data-in-SYN.
						  */
	u8				syn_tos;
	bool				accecn_ok;
	u8				syn_ect_snt: 2,
					syn_ect_rcv: 2,
					accecn_fail_mode:4;
	u8				saw_accecn_opt  :2;
#ifdef CONFIG_TCP_AO
	u8				ao_keyid;
	u8				ao_rcv_next;
	bool				used_tcp_ao;
#endif
};

#define tcp_rsk(ptr) container_of_const(ptr, struct tcp_request_sock, req.req)

static inline bool tcp_rsk_used_ao(const struct request_sock *req)
{
#ifndef CONFIG_TCP_AO
	return false;
#else
	return tcp_rsk(req)->used_tcp_ao;
#endif
}

#define TCP_RMEM_TO_WIN_SCALE 8

struct tcp_sock {
	/* Cacheline organization can be found documented in
	 * Documentation/networking/net_cachelines/tcp_sock.rst.
	 * Please update the document when adding new fields.
	 */

	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;

	/* TX read-mostly hotpath cache lines */
	__cacheline_group_begin(tcp_sock_read_tx);
	u32	max_window;	/* Maximal window ever seen from peer	*/
	/* 收包的慢启动阈值？当可用内存小于这个的时候，就尝试扩大窗口 */
	u32	rcv_ssthresh;	/* Current window clamp			*/
	u32	reordering;	/* Packet reordering metric.		*/
	u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */
	/* 一个skb中能够存储的seg最大数量 */
	u16	gso_segs;	/* Max number of segs per GSO packet	*/
	/* from STCP, retrans queue hinting */
	struct sk_buff *retransmit_skb_hint;
#if defined(CONFIG_TLS_DEVICE)
	void (*tcp_clean_acked)(struct sock *sk, u32 acked_seq);
#endif
	__cacheline_group_end(tcp_sock_read_tx);

	/* TXRX read-mostly hotpath cache lines */
	__cacheline_group_begin(tcp_sock_read_txrx);
	u32	tsoffset;	/* timestamp offset */
	/* 发送窗口大小（SYN协商出来的那个）。 */
	u32	snd_wnd;	/* The window we expect to receive	*/
	/* 当前生效的MSS，不会超过 mss_clamp 的大小 */
	u32	mss_cache;	/* Cached effective mss, not including SACKS */
	u32	snd_cwnd;	/* Sending congestion window		*/
	/* 拥塞状态下，所有发送出去的数据，包括重传的数据。 */
	u32	prr_out;	/* Total number of pkts sent during Recovery. */
	u32	lost_out;	/* Lost packets			*/
	/*
	 * 对于不支持SACK的场景，使用reno算法。该字段用于为该算法服务，
	 * 用于记录重复ACK的数量。
	 */
	u32	sacked_out;	/* SACK'd packets			*/
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	u8	scaling_ratio;	/* see tcp_win_from_space() */
	u8	chrono_type : 2,	/* current chronograph type */
		repair      : 1,
		tcp_usec_ts : 1, /* TSval values in usec */
		is_sack_reneg:1,    /* in recovery from loss with SACK reneg? */
		/* 数据的发送被拥塞窗口限制住了。 */
		is_cwnd_limited:1,/* forward progress limited by snd_cwnd? */
		recvmsg_inq : 1;/* Indicate # of bytes in queue upon recvmsg */
	__cacheline_group_end(tcp_sock_read_txrx);

	/* RX read-mostly hotpath cache lines */
	__cacheline_group_begin(tcp_sock_read_rx);
	/* 已经拷贝到用户态的最后一个序列号 */
	u32	copied_seq;	/* Head of yet unread data */
	u32	snd_wl1;	/* Sequence for window update		*/
	u32	tlp_high_seq;	/* snd_nxt at the time of TLP */
	/* 平滑版本的 mdev_max */
	u32	rttvar_us;	/* smoothed mdev_max			*/
	/* 已经发送出去，还没被确认的重传数据 */
	u32	retrans_out;	/* Retransmitted packets out		*/
	u16	advmss;		/* Advertised MSS			*/
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u32	lost;		/* Total data packets lost incl. rexmits */
	u32	snd_ssthresh;	/* Slow start size threshold		*/
	/* 根据最后一个被ack的报文计算出来的rtt */
	struct  minmax rtt_min;
	/* OOO segments go in this rbtree. Socket lock must be held. */
	struct rb_root	out_of_order_queue;
	__cacheline_group_end(tcp_sock_read_rx);

	/* TX read-write hotpath cache lines */
	__cacheline_group_begin(tcp_sock_write_tx) ____cacheline_aligned;
	u32	segs_out;	/* RFC4898 tcpEStatsPerfSegsOut
				 * The total number of segments sent.
				 */
	u32	data_segs_out;	/* RFC4898 tcpEStatsPerfDataSegsOut
				 * total number of data segments sent.
				 */
	u64	bytes_sent;	/* RFC4898 tcpEStatsPerfHCDataOctetsOut
				 * total number of data bytes sent.
				 */
	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	u32	chrono_start;	/* Start time in jiffies of a TCP chrono */
	/* 记录了TCP套接口处于各种状态的时间，包括BUSY（发送数据）、RWND_LIMITED（零窗口）
	 * SND_LIMITED（发送窗口受限）等。
	 */
	u32	chrono_stat[3];	/* Time in jiffies for chrono_stat stats */
	/* 要设置到下一个存放到发送队列的报文的序列号 */
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
	u32	mdev_us;	/* medium deviation			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/
	/* 这个看样子和tcp_mstamp是一致的哦，只不过这个针对的是发送报文的，这个时间会
	 * 在发送报文的时候被更新，并设置到发送报文里面。
	 */
	u64	tcp_wstamp_ns;	/* departure time for next sent data packet */
	u64	accecn_opt_tstamp;	/* Last AccECN option sent timestamp */
	/* 每次发送报文的时候会被加入到这个队列，报文被ack或者sack后会被移除这个队列。
	 * 报文被标记为lost也会被移除，再重传的时候又会被重新加入到这个队列。可以看
	 * 出来，这个队列是按照发送顺序排列的。
	 */
	struct list_head tsorted_sent_queue; /* time-sorted sent but un-SACKed skbs */
	struct sk_buff *highest_sack;   /* skb just after the highest
					 * skb with SACKed bit set
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */
	u8	ecn_flags;	/* ECN status bits.			*/
	__cacheline_group_end(tcp_sock_write_tx);

	/* TXRX read-write hotpath cache lines */
	__cacheline_group_begin(tcp_sock_write_txrx);
/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	u8	nonagle     : 4,/* Disable Nagle algorithm?             */
		rate_app_limited:1;  /* rate_{delivered,interval_us} limited? */
	u8	received_ce_pending:4, /* Not yet transmit cnt of received_ce */
		accecn_opt_sent_w_dsack:1,/* Sent ACCECN opt in previous ACK w/ D-SACK */
		unused2:3;
	u8	accecn_minlen:2,/* Minimum length of AccECN option sent */
		est_ecnfield:2,/* ECN field for AccECN delivered estimates */
		accecn_opt_demand:2,/* Demand AccECN option for n next ACKs */
		prev_ecnfield:2; /* ECN bits from the previous segment */
	__be32	pred_flags;
	u64	tcp_clock_cache; /* cache last tcp_clock_ns() (see tcp_mstamp_refresh()) */
	/* 最近一次收到或者发送报文的时间戳，约等于当前时间，它的单位是us。在以下情况
	 * 下，它会被刷新：
	 * - 套接口刚创建（完成三次握手，tcp_init_transfer函数中）
	 * - 关闭TCP_REPAIR的时候，发送窗口探测
	 * - 发送延迟ACK报文（**压缩ack没有刷新*）
	 * - 写定时器超时、保活定时器超时
	 * - 发送rst的时候
	 * - 收到或者发送携带数据的报文之前。
	 * 可以看出来，在任何报文发送之前，都会刷新这个mstamp，包括ack报文。
	 */
	u64	tcp_mstamp;	/* most recent packet received/sent */
	/* 下一个要接收的数据 */
	u32	rcv_nxt;	/* What we want to receive next		*/
	/* 下一个要发送的数据，也就是当前窗口已发送的最后一个数据。也可以理解为发送
	 * 队列中的第一个数据。
	 */
	u32	snd_nxt;	/* Next sequence we send		*/
	/* 当前发送窗口的第一个字节，也可以理解为重传队列中的第一个数据。*/
	u32	snd_una;	/* First byte we want an ack for	*/
	u32	window_clamp;	/* Maximal window to advertise		*/
	/* 平滑版本的rtt，不至于导致单次rtt的波动引发rtt的大幅波动，按照
	 * rtt = 7/8 rtt + 1/8 new 计算出来的。
	 */
	u32	srtt_us;	/* smoothed round trip time << 3 in usecs */
	u32	packets_out;	/* Packets which are "in flight"	*/
	u32	snd_up;		/* Urgent pointer		*/
	/* 累计的被ack/sack的报文的数量 */
	u32	delivered;	/* Total data packets delivered incl. rexmits */
	u32	delivered_ce;	/* Like the above but only ECE marked packets */
	u32	received_ce;	/* Like the above but for rcvd CE marked pkts */
	u32	received_ecn_bytes[3]; /* received byte counters for three ECN
					* types: INET_ECN_ECT_1, INET_ECN_ECT_0,
					* and INET_ECN_CE
					*/
	/* 代表当前的TCP传输是否是用户没有发送足够的数据下来导致带宽受限，这个值是在
	 * 发现受限的时候已经被确认的数据量+in flight，即：
	 *   app_limited - delivered = in flight
	 */
	u32	app_limited;	/* limited until "delivered" reaches this val */
	/* 当前接收窗口的大小 */
	u32	rcv_wnd;	/* Current receiver window		*/
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	/* 套接口层面的TCP接收选项，一般是取的最后一个skb上的。对于一些配置，也会取
	 * SYN上的，比如MSS等。
	 */
	struct tcp_options_received rx_opt;
	__cacheline_group_end(tcp_sock_write_txrx);

	/* RX read-write hotpath cache lines */
	__cacheline_group_begin(tcp_sock_write_rx) __aligned(8);
	u64	bytes_received;
				/* RFC4898 tcpEStatsAppHCThruOctetsReceived
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
	u32	segs_in;	/* RFC4898 tcpEStatsPerfSegsIn
				 * total number of segments in.
				 */
	u32	data_segs_in;	/* RFC4898 tcpEStatsPerfDataSegsIn
				 * total number of data segments in.
				 */
	/* 
	 * 只有当我们在 tcp_select_window() 中发送 ACK 时，tp->rcv_wup 才与
	 * 要接收的下一个字节（tp->rcv_nxt）同步。
	 * 也就是说，rcv_wup指的是已经收到的连续报文的还未发送ACK的数据的最大序列号，
	 * 其<=rcv_nxt。可以看出来，这个属性是用来延迟发送ACK的，即进行数据的累加
	 * 确认。
	 */
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
	u32	max_packets_out;  /* max packets_out in last window */
	u32	cwnd_usage_seq;  /* right edge of cwnd usage tracking flight */
	/* 根据对被确认的报文的采样计算（预估）出来的当前流的真实的带宽 */
	u32	rate_delivered;    /* saved rate sample: packets delivered */
	u32	rate_interval_us;  /* saved rate sample: time elapsed */
	u32	rcv_rtt_last_tsecr;
	u32	delivered_ecn_bytes[3];
	u16	pkts_acked_ewma;/* Pkts acked EWMA for AccECN cep heuristic */
	u64	first_tx_mstamp;  /* start of window send phase */
	u64	delivered_mstamp; /* time we reached "delivered" */
	u64	bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
	struct {
		u32	rtt_us;
		/* 上一次收到数据的序列号 */
		u32	seq;
		/* 上一次收到数据的时间戳 */
		u64	time;
	} rcv_rtt_est;
/* Receiver queue space */
	struct {
		int	space;
		u32	seq;
		u64	time;
	} rcvq_space;
	__cacheline_group_end(tcp_sock_write_rx);
	/* End of Hot Path */

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
	/* 收到的DSACK确认的伪重传的段数 */
	u32	dsack_dups;	/* RFC4898 tcpEStatsStackDSACKDups
				 * total number of DSACK blocks received
				 */
	u32	compressed_ack_rcv_nxt;
	struct list_head tsq_node; /* anchor in tsq_tasklet.head list */

	/*
	 * rack算法相关的实现。rack（recent ack）是一种探测丢包的方法，与快速重传算法
	 * 并驾齐驱。
	 *
	 * 算法思想：
	 * 1、每次收到ack，先更新rtt_min，然后更新乱序时间窗口reo_wnd
	 *   （reo_wnd=max(rtt_min/4, 1ms)）；
	 * 2、更新最新的被确认的数据包的发送时间，在mstamp中，其中advanced表示mstamp
	 *   是否被更新过。这里的最新的指的是发送时间最大的被sack确认的报文。
	 * 3、将符合条件的包标记为丢失。对于所有的已经发送的报文，如果其发送时间距离mstamp
	 *   超过了reo_wnd，那么将其标记为lost。
	 *
	 * 基本思想很简单：对于已经被sack确认的前面的未被确认的报文，如果时间差超过了乱序
	 * 的阀值，那么认为其已经丢失。
	 */
	struct tcp_rack {
		u64 mstamp; /* (Re)sent time of the skb */
		u32 rtt_us;  /* Associated RTT */
		u32 end_seq; /* Ending TCP sequence of the skb */
		u32 last_delivered; /* tp->delivered at last reo_wnd adj */
		u8 reo_wnd_steps;   /* Allowed reordering window */
#define TCP_RACK_RECOVERY_THRESH 16
		u8 reo_wnd_persist:5, /* No. of recovery since last adj */
		   dsack_seen:1, /* Whether DSACK seen after last adj */
		   advanced:1;	 /* mstamp advanced since last lost marking */
	} rack;
	u8	compressed_ack;
	u8	dup_ack_counter:2,
		tlp_retrans:1,	/* TLP is a retransmission */
		syn_ect_snt:2,	/* AccECN ECT memory, only */
		syn_ect_rcv:2;	/* ... needed during 3WHS + first seqno */
	u8	thin_lto    : 1,/* Use linear timeouts for thin streams */
		fastopen_connect:1, /* FASTOPEN_CONNECT sockopt */
		fastopen_no_cookie:1, /* Allow send/recv SYN+data without a cookie */
		fastopen_client_fail:2, /* reason why fastopen failed */
	/*
	 * 标记是否启用了FRTO算法。如果启用了该算法，那么TCP依然会进入LOSS状态，
	 * 只不过在LOSS处理过程中会先判断FRTO的状态，再决定是否真的进入恢复状态。
	 */
		frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */
	u8	repair_queue;
	u8	save_syn:2,	/* Save headers of SYN packet */
		syn_data:1,	/* SYN includes data */
		syn_fastopen:1,	/* SYN includes Fast Open option */
		syn_fastopen_exp:1,/* SYN includes Fast Open exp. option */
		syn_fastopen_ch:1, /* Active TFO re-enabling probe */
		syn_data_acked:1,/* data in SYN is acked by SYN-ACK */
		syn_fastopen_child:1; /* created TFO passive child socket */

	u8	keepalive_probes; /* num of allowed keep alive probes	*/
	u8	accecn_fail_mode:4,	/* AccECN failure handling */
		saw_accecn_opt:2;	/* An AccECN option was seen */
	u32	tcp_tx_delay;	/* delay (in usec) added to TX packets */

/* RTT measurement */
	u32	mdev_max_us;	/* maximal mdev for the last rtt period	*/

	u32	reord_seen;	/* number of data packet reordering events */

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
	/* 拥塞窗口计数，统计本次窗口内报文的累计发送量。 */
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	/* 拥塞窗口的上限值。 */
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp;
	u32	prior_cwnd;	/* cwnd right before starting loss recovery */
	/* 拥塞状态下，新发送的数据 */
	u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
	u32	last_oow_ack_time;  /* timestamp of last out-of-window ACK */

	struct hrtimer	pacing_timer;
	struct hrtimer	compressed_ack_timer;

	struct sk_buff	*ooo_last_skb; /* cache rb_last(out_of_order_queue) */

	/* SACKs data, these 2 need to be together (see tcp_options_write) */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	/* 选择确认块，里面存储了已经接收到的乱序的连续的数据块。在收到乱序的报文的
	 * 时候，会调用tcp_sack_new_ofo_skb来更新这里的数据。
	 */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4];

	/* 先前保存的拥塞阀值，用于进行恢复，比如发现了伪重传等。 */
	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	/* TCP拥塞控制的恢复点 */
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	/* 最后一个重传的报文的发送时间，可用于基于TS的伪超时检测。 */
	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* snd_una upon a new recovery episode. */
	/* 可撤销的重传计数，即在可撤销拥塞状态重传的报文数量。 */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	mtu_info; /* We received an ICMP_FRAG_NEEDED / ICMPV6_PKT_TOOBIG
			   * while socket was owned by user.
			   */
	u64	bytes_retrans;	/* RFC4898 tcpEStatsPerfOctetsRetrans
				 * Total data bytes retransmitted
				 */
	/* 当前套接口上总共重传的数据段的数量，减去伪重传的段数即可算出丢包重传的段数 */
	u32	total_retrans;	/* Total retransmits for entire connection */
	u32	rto_stamp;	/* Start time (ms) of last CA_Loss recovery */
	u16	total_rto;	/* Total number of RTO timeouts, including
				 * SYN/SYN-ACK and recurring timeouts.
				 */
	u16	total_rto_recoveries;	/* Total number of RTO recoveries,
					 * including any unfinished recovery.
					 */
	/* 处于LOSS状态下的时间的总和，即每次进入LOST和退出LOST的时间差的和 */
	u32	total_rto_time;	/* ms spent in (completed) RTO recoveries. */

	u32	urg_seq;	/* Seq of received urgent pointer */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

	/* TCP套接口在FIN_WAIT2状态下的超时时间，通过TCP_LINGER2选项设置。没有设置
	 * 的话就取默认的sysctl_tcp_fin_timeout。如果小于0的话，会不经过FIN_WAIT2，
	 * 直接进行RST断链。
	 */
	int			linger2;


/* Sock_ops bpf program related variables */
#ifdef CONFIG_BPF
	u8	bpf_sock_ops_cb_flags;  /* Control calling BPF programs
					 * values defined in uapi/linux/tcp.h
					 */
	u8	bpf_chg_cc_inprogress:1; /* In the middle of
					  * bpf_setsockopt(TCP_CONGESTION),
					  * it is to avoid the bpf_tcp_cc->init()
					  * to recur itself by calling
					  * bpf_setsockopt(TCP_CONGESTION, "itself").
					  */
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) (TP->bpf_sock_ops_cb_flags & ARG)
#else
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) 0
#endif

	u16 timeout_rehash;	/* Timeout-triggered rehash attempts */

	u32 rcv_ooopack; /* Received out-of-order packets, for tcpinfo */

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;
	u32     plb_rehash;     /* PLB-triggered rehash attempts */
#if IS_ENABLED(CONFIG_MPTCP)
	bool	is_mptcp;
#endif
#if IS_ENABLED(CONFIG_SMC)
	bool	syn_smc;	/* SYN includes SMC */
	bool	(*smc_hs_congested)(const struct sock *sk);
#endif

#if defined(CONFIG_TCP_MD5SIG) || defined(CONFIG_TCP_AO)
/* TCP AF-Specific parts; only used by TCP-AO/MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

#ifdef CONFIG_TCP_MD5SIG
/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	__rcu *md5sig_info;
#endif
#ifdef CONFIG_TCP_AO
	struct tcp_ao_info	__rcu *ao_info;
#endif
#endif

/* TCP fastopen related information */
	struct tcp_fastopen_request *fastopen_req;
	/* fastopen_rsk points to request_sock that resulted in this big
	 * socket. Used to retransmit SYNACKs etc.
	 */
	struct request_sock __rcu *fastopen_rsk;
	struct saved_syn *saved_syn;
};

enum tsq_enum {
	TSQ_THROTTLED,
	TSQ_QUEUED,
	TCP_TSQ_DEFERRED,	   /* tcp_tasklet_func() found socket was owned */
	TCP_WRITE_TIMER_DEFERRED,  /* tcp_write_timer() found socket was owned */
	TCP_DELACK_TIMER_DEFERRED, /* tcp_delack_timer() found socket was owned */
	TCP_MTU_REDUCED_DEFERRED,  /* tcp_v{4|6}_err() could not call
				    * tcp_v{4|6}_mtu_reduced()
				    */
	TCP_ACK_DEFERRED,	   /* TX pure ack is deferred */
};

enum tsq_flags {
	TSQF_THROTTLED			= BIT(TSQ_THROTTLED),
	TSQF_QUEUED			= BIT(TSQ_QUEUED),
	TCPF_TSQ_DEFERRED		= BIT(TCP_TSQ_DEFERRED),
	TCPF_WRITE_TIMER_DEFERRED	= BIT(TCP_WRITE_TIMER_DEFERRED),
	TCPF_DELACK_TIMER_DEFERRED	= BIT(TCP_DELACK_TIMER_DEFERRED),
	TCPF_MTU_REDUCED_DEFERRED	= BIT(TCP_MTU_REDUCED_DEFERRED),
	TCPF_ACK_DEFERRED		= BIT(TCP_ACK_DEFERRED),
};

#define tcp_sk(ptr) container_of_const(ptr, struct tcp_sock, inet_conn.icsk_inet.sk)

/* Variant of tcp_sk() upgrading a const sock to a read/write tcp socket.
 * Used in context of (lockless) tcp listeners.
 */
#define tcp_sk_rw(ptr) container_of(ptr, struct tcp_sock, inet_conn.icsk_inet.sk)

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
#define tw_rcv_nxt tw_sk.__tw_common.skc_tw_rcv_nxt
#define tw_snd_nxt tw_sk.__tw_common.skc_tw_snd_nxt
	u32			  tw_rcv_wnd;
	u32			  tw_ts_offset;
	u32			  tw_ts_recent;

	/* The time we sent the last out-of-window ACK: */
	u32			  tw_last_oow_ack_time;

	int			  tw_ts_recent_stamp;
	u32			  tw_tx_delay;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key	  *tw_md5_key;
#endif
#ifdef CONFIG_TCP_AO
	struct tcp_ao_info	__rcu *ao_info;
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

static inline bool tcp_passive_fastopen(const struct sock *sk)
{
	return sk->sk_state == TCP_SYN_RECV &&
	       rcu_access_pointer(tcp_sk(sk)->fastopen_rsk) != NULL;
}

static inline void fastopen_queue_tune(struct sock *sk, int backlog)
{
	struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;
	int somaxconn = READ_ONCE(sock_net(sk)->core.sysctl_somaxconn);

	WRITE_ONCE(queue->fastopenq.max_qlen, min_t(unsigned int, backlog, somaxconn));
}

static inline void tcp_move_syn(struct tcp_sock *tp,
				struct request_sock *req)
{
	tp->saved_syn = req->saved_syn;
	req->saved_syn = NULL;
}

static inline void tcp_saved_syn_free(struct tcp_sock *tp)
{
	kfree(tp->saved_syn);
	tp->saved_syn = NULL;
}

static inline u32 tcp_saved_syn_len(const struct saved_syn *saved_syn)
{
	return saved_syn->mac_hdrlen + saved_syn->network_hdrlen +
		saved_syn->tcp_hdrlen;
}

struct sk_buff *tcp_get_timestamping_opt_stats(const struct sock *sk,
					       const struct sk_buff *orig_skb,
					       const struct sk_buff *ack_skb);

static inline u16 tcp_mss_clamp(const struct tcp_sock *tp, u16 mss)
{
	/* We use READ_ONCE() here because socket might not be locked.
	 * This happens for listeners.
	 */
	u16 user_mss = READ_ONCE(tp->rx_opt.user_mss);

	return (user_mss && user_mss < mss) ? user_mss : mss;
}

int tcp_skb_shift(struct sk_buff *to, struct sk_buff *from, int pcount,
		  int shiftlen);

void __tcp_sock_set_cork(struct sock *sk, bool on);
void tcp_sock_set_cork(struct sock *sk, bool on);
int tcp_sock_set_keepcnt(struct sock *sk, int val);
int tcp_sock_set_keepidle_locked(struct sock *sk, int val);
int tcp_sock_set_keepidle(struct sock *sk, int val);
int tcp_sock_set_keepintvl(struct sock *sk, int val);
void __tcp_sock_set_nodelay(struct sock *sk, bool on);
void tcp_sock_set_nodelay(struct sock *sk);
void tcp_sock_set_quickack(struct sock *sk, int val);
int tcp_sock_set_syncnt(struct sock *sk, int val);
int tcp_sock_set_user_timeout(struct sock *sk, int val);
int tcp_sock_set_maxseg(struct sock *sk, int val);

static inline bool dst_tcp_usec_ts(const struct dst_entry *dst)
{
	return dst_feature(dst, RTAX_FEATURE_TCP_USEC_TS);
}

#endif	/* _LINUX_TCP_H */
