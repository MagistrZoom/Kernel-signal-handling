#include <linux/module.h>
#include <linux/kernel.h>	
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <trace/events/signal.h>

//set to execute shell command
#define SIG_USR ((__force __sighandler_t)2) 
//process-defined behaviour
#define SIG_PROC ((__force __sighandler_t)3)

static struct tracepoint *signal_deliver_tp = NULL;
static struct tracepoint *signal_generate_tp = NULL;
struct signal_intercept {
	int sig;
	__sighandler_t sig_handler;
	void *cmd;
};

static struct signal_intercept interceptors[_NSIG] = {0};


static void signal_deliver_probe(
		void *data, int sig, struct siginfo *info, struct k_sigaction *ka)
{
	printk(KERN_INFO "SIG delivered:%d with handler %p and action %p", sig, ka->sa.sa_handler, interceptors[sig].sig_handler); //log
	
	if(interceptors[sig].sig_handler == SIG_PROC){
		return;
	}
	//looking for changed signal handers	
	if(interceptors[sig].sig_handler == SIG_DFL){
		ka->sa.sa_handler = SIG_DFL;
		return;
	}
	if(interceptors[sig].sig_handler == SIG_IGN){
		printk("Force ignoring %d signal", sig);
		ka->sa.sa_handler = SIG_IGN;
		return;
	}
	if(interceptors[sig].sig_handler == SIG_USR){
		//do some things from interceptors[sig]->cmd
		//
		//end dat

		ka->sa.sa_handler = SIG_IGN;
	}
}

static void 
signal_generate_probe(void *data, int sig, struct siginfo *info, 
	struct task_struct *task, int group, int result)
{
	printk(KERN_INFO "SIG generated:%d to pid %d", sig, task->pid); //log
}


static void find_signal_deliver(struct tracepoint *tp, void *priv) 
{
	if (!strcmp(tp->name, "signal_deliver")){
		signal_deliver_tp = tp;
	}
}

static void find_signal_generate(struct tracepoint *tp, void *priv) 
{
	if (!strcmp(tp->name, "signal_generate")){
		signal_generate_tp = tp;
	}
}

static int connect_probes(void) 
{
	int ret;
	for_each_kernel_tracepoint(find_signal_deliver, NULL);

	if (!signal_deliver_tp)
		return -ENODEV;

	ret = tracepoint_probe_register(signal_deliver_tp,
					signal_deliver_probe, NULL);

	if (ret)
		return ret;

	for_each_kernel_tracepoint(find_signal_generate, NULL);

	if (!signal_generate_tp)
		return -ENODEV;

	ret = tracepoint_probe_register(signal_generate_tp,
					signal_generate_probe, NULL);

	if (ret)
		return ret;
	
	return 0;
}

static int __init load_module(void) 
{
	printk(KERN_INFO "+Module load\n");

	int i;

	for(i = 0; i < _NSIG; i++){
		interceptors[i] = (struct signal_intercept){
			.sig = i,
			.sig_handler = SIG_PROC,
			.cmd = NULL
		};
	}

	interceptors[SIGUSR1] = (struct signal_intercept){
		.sig = SIGUSR1,
		.sig_handler = SIG_IGN,
		.cmd = NULL		
	};	

	connect_probes();
	return 0;
}

static void __exit unload_module(void) 
{
	if (signal_deliver_tp)
		tracepoint_probe_unregister(signal_deliver_tp,
    signal_deliver_probe, NULL);

	if (signal_generate_tp)
		tracepoint_probe_unregister(signal_generate_tp,
    signal_generate_probe, NULL);

	tracepoint_synchronize_unregister();
	
	printk(KERN_INFO "+Module unload\n");
}


module_init(load_module);
module_exit(unload_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vladimir iZoomko Gubarev <izoomko@techstories.ru>");
MODULE_DESCRIPTION("signal intercepting");
