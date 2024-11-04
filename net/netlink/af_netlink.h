/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AF_NETLINK_H
#define _AF_NETLINK_H

#include <linux/rhashtable.h>
#include <linux/atomic.h>
#include <net/sock.h>

/* flags */
enum {
	NETLINK_F_KERNEL_SOCKET,
	NETLINK_F_RECV_PKTINFO,
	NETLINK_F_BROADCAST_SEND_ERROR,
	NETLINK_F_RECV_NO_ENOBUFS,
	NETLINK_F_LISTEN_ALL_NSID,
	NETLINK_F_CAP_ACK,
	NETLINK_F_EXT_ACK,
	NETLINK_F_STRICT_CHK,
};

#define NLGRPSZ(x)	(ALIGN(x, sizeof(unsigned long) * 8) / 8)
#define NLGRPLONGS(x)	(NLGRPSZ(x)/sizeof(unsigned long))

struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	unsigned long		flags;
	/* netlink套接口的端口。可以看出来，netlink套接口也是有端口的概念的，同时
	 * 它也有group的概念，bind的时候可以绑定端口和group。这里的端口需要是唯一
	 * 的，每个协议对应的内核的那个端口的端口号为0，用来进行内核和用户态之间
	 * 的通信。
	 */
	u32			portid;
	u32			dst_portid;
	u32			dst_group;
	u32			subscriptions;
	u32			ngroups;
	/* 当前的套接口监听的多播group列表。当套接口使用bind进行group绑定的时候，
	 * 这个套接口会被加入到当前协议的nl_table的mc_list链表中，在进行事件的
	 * notify的时候会遍历这个链表，并匹配事件的group和套接口的group，在匹配
	 * 到的时候进行skb的发送。
	 */
	unsigned long		*groups;
	unsigned long		state;
	size_t			max_recvmsg_len;
	wait_queue_head_t	wait;
	bool			bound;
	bool			cb_running;
	int			dump_done_errno;
	struct netlink_callback	cb;
	struct mutex		nl_cb_mutex;

	void			(*netlink_rcv)(struct sk_buff *skb);
	/* 这个钩子函数仅仅用来进行多播group的绑定 */
	int			(*netlink_bind)(struct net *net, int group);
	void			(*netlink_unbind)(struct net *net, int group);
	void			(*netlink_release)(struct sock *sk,
						   unsigned long *groups);
	struct module		*module;

	struct rhash_head	node;
	struct rcu_head		rcu;
};

static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

#define nlk_test_bit(nr, sk) test_bit(NETLINK_F_##nr, &nlk_sk(sk)->flags)

struct netlink_table {
	/* 所有的当前协议的套接口都会被放到这个哈希表中。对于启用的协议，其必定
	 * 存在一个内核创建的dummy性质的套接口。
	 */
	struct rhashtable	hash;
	struct hlist_head	mc_list;
	struct listeners __rcu	*listeners;
	unsigned int		flags;
	unsigned int		groups;
	struct mutex		*cb_mutex;
	struct module		*module;
	int			(*bind)(struct net *net, int group);
	void			(*unbind)(struct net *net, int group);
	void                    (*release)(struct sock *sk,
					   unsigned long *groups);
	int			registered;
};

extern struct netlink_table *nl_table;
extern rwlock_t nl_table_lock;

#endif
