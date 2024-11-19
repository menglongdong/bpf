# TC 流量控制

## 基本概念

### Qdisc

排队队列。可以理解为报文的调度器，用来调度哪些报文以什么样的方式发送出去。Qdisc又分为有类
和无类队列，其区别是是否能有子队列。

HTB队列添加方法：
`#tc qdisc add dev eth0 root handle 1: htb default 1:11`
其中`default 1:11`代表所有未分类的报文都分配给`1:11`。

### class和filter

类别与过滤器（分类器）是对应关系的，通过两者的结合，使得有类类型的Qdisc可以以树状结构来组
织。每个有类队列可以有若干个类别，每个类别可以有若干个子类或者队列。而分类器用于决定报文
交给那个子类别来处理。

下面的命令为root队列添加了三个类别，且每个类别都有一个htb队列，其中rate代表当前分类的
限速：

```shell
#tc class add dev eth0 parent 1: classid 1:11 htb rate 40mbit ceil 40mbit
#tc class add dev eth0 parent 1: classid 1:12 htb rate 40mbit ceil 40mbit
#tc class add dev eth0 parent 1: classid 1:13 htb rate 20mbit ceil 20mbit
```

下面的命令为root创建了三个过滤器，用于将报文分配到各个类别中：
```shell
#tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dport 80 0xffff flowid 1:11
#tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dport 25 0xffff flowid 1:12
#tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dport 23 oxffff flowid 1:13
```