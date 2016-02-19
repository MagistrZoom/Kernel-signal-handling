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

/*
 * Copy from kernel/signal.c
 * (next_signal is unexported symbol :<)
 *
 */

/* Given the mask, find the first available signal that should be serviced. */

#define SYNCHRONOUS_MASK \
	(sigmask(SIGSEGV) | sigmask(SIGBUS) | sigmask(SIGILL) | \
	 sigmask(SIGTRAP) | sigmask(SIGFPE) | sigmask(SIGSYS))

int select_next_signal(struct sigpending *pending, sigset_t *mask)
{
	unsigned long i, *s, *m, x;
	int sig = 0;

	s = pending->signal.sig;
	m = mask->sig;

	/*
	 * Handle the first word specially: it contains the
	 * synchronous signals that need to be dequeued first.
	 */
	x = *s &~ *m;
	printk(KERN_ALERT "+Some shi inside next_sigal in my module %lu", x);
	if (x) {
		if (x & SYNCHRONOUS_MASK)
			x &= SYNCHRONOUS_MASK;
		sig = ffz(~x) + 1;
		printk(KERN_ALERT "+inside next_signal |if(x).. signr (%d)",sig);
		return sig;
	}

	switch (_NSIG_WORDS) {
	default:
		for (i = 1; i < _NSIG_WORDS; ++i) {
			x = *++s &~ *++m;
			if (!x)
				continue;
			sig = ffz(~x) + i*_NSIG_BPW + 1;
			printk(KERN_ALERT "+inside next_signal |switch default.. signr (%d)",sig);
			break;
		}
		break;

	case 2:
		x = s[1] &~ m[1];
		if (!x)
			break;
		sig = ffz(~x) + _NSIG_BPW + 1;
		printk(KERN_ALERT "inside next_signal |switch case 2.. signr (%d)",sig);
		break;

	case 1:
		/* Nothing to do */
		break;
	}

	return sig;
}

/*
 * @func signal_deliver_probe
 * @desc probe invoked by signal_deliver tracepoint
 * @param (void*) data - custom info set by tracepoint_probe_register
 * @param (int) sig - received signal
 * @param (struct siginfo *)info struct, part of ksig variable from do_signal
 * @param (struct k_sigaction*) sig action handler
 * @return: (void)
 */
static void signal_deliver_probe(
		void *data, int sig, struct siginfo *info, struct k_sigaction *ka)
{
	int signr = sig;
	rcu_read_lock(); //code below is not multithreaded 
	struct sigpending *pending = &current->pending;                         
	struct signal_struct *signal = current->signal;    

	/*
	 * there is no way to receive SIGKILL without a death-signal
	 * so then look for next signal by dequeue_signal	
	 *
	 */

	if(sig == SIGKILL) { 
		signr = select_next_signal(&signal->shared_pending, &current->blocked);
		//signr = dequeue_signal(current, &current->blocked, info);
		if(sig_fatal(current,signr) && interceptors[signr].sig_handler != SIG_PROC){ 
			/*
			 * oh, nice! we've got fatal handled signal and now we should manage
			 * orig signal instead of SIGKILL
			 * 
			 * remove SIGNAL_GROUP_EXIT from signal->flags of process to make
			 * next exit code valid
			 */
			sig = signr;
			signal->flags &= ~SIGNAL_GROUP_EXIT;

			printk(KERN_DEBUG "+Signal following by SIKGILL is (%d)", signr);
		}
	}

	printk(KERN_INFO "+SIG delivered:%d with ka handler %p and action %p", 
			sig, ka->sa.sa_handler, interceptors[sig].sig_handler); //log
	
	switch((unsigned long)interceptors[sig].sig_handler) {
		case (unsigned long)SIG_PROC:
			break;
		case (unsigned long)SIG_DFL:
			printk(KERN_DEBUG "+Force default action for (%d)", sig);
			ka->sa.sa_handler = SIG_DFL;
			break;
		case (unsigned long)SIG_USR:
			//do some things 
		case (unsigned long)SIG_IGN:
			printk(KERN_DEBUG "+Usr defined handler or ignored sig (%d) ", sig);
			ka->sa.sa_handler = SIG_IGN;
			break;
	}
	/* 
	 * if there was few signals which could kill process 
	 * need to restore SIGKILL and set up valid return code
	 *
	 */
	int sign;
	for(sign = 0; sign < _NSIG; sign++){
		if(sigismember(&pending->signal, sign) && sig_fatal(current, sign)){
			signal->flags = SIGNAL_GROUP_EXIT;                                 
			signal->group_exit_code = sign;                                     
			signal->group_stop_count = 0;                                      

	 	    sigaddset(&pending->signal, SIGKILL);                        
			printk(KERN_DEBUG "+Besides (%d) there was (%d) also. Set up new exit code and SIGNAL_GROUP_EXIT", sig, sign);
			break;
		}
	}
	rcu_read_unlock();
	return;
}

static void 
signal_generate_probe(void *data, int sig, struct siginfo *info, 
	struct task_struct *task, int group, int result)
{
	printk(KERN_INFO "+SIG generated:%d to pid %d", sig, task->pid); //log
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
