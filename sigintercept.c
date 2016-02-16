#include <linux/module.h>
#include <linux/kernel.h>	
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <trace/events/signal.h>

static struct tracepoint *signal_deliver_tp = NULL;


static void signal_deliver_probe(void *data, int sig, struct siginfo *info, struct k_sigaction *ka) {
	printk(KERN_INFO "SIG:%d siginfo:%p in %s %d", sig, info,  __FUNCTION__, __LINE__);
}

static void find_signal_deliver(struct tracepoint *tp, void *priv) {
	if (!strcmp(tp->name, "signal_deliver")){
		printk(KERN_INFO "%s", tp->name);
		signal_deliver_tp = tp;
	}
}

static int connect_probes(void) {
	int ret;
	for_each_kernel_tracepoint(find_signal_deliver, NULL);

	if (!signal_deliver_tp)
		return -ENODEV;

	ret = tracepoint_probe_register(signal_deliver_tp,
					signal_deliver_probe, NULL);

	if (ret)
		return ret;
	
	return 0;
}

static int __init load_module(void) {
	printk(KERN_INFO "+Module load\n");
	
	connect_probes();
	return 0;
}

static void __exit unload_module(void) {
	if (signal_deliver_tp)
		tracepoint_probe_unregister(signal_deliver_tp,
    signal_deliver_probe, NULL);

	tracepoint_synchronize_unregister();
	
	printk(KERN_INFO "+Module unload\n");
}










module_init(load_module);
module_exit(unload_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vladimir iZoomko Gubarev <izoomko@techstories.ru>");
MODULE_DESCRIPTION("signal handling");
