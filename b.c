#include <linux/module.h>
#include <linux/kernel.h>	
#include <linux/init.h>

#include <linux/tracepoint.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <trace/events/signal.h>

//set to execute shell command
#define SIG_USR ((__force __sighandler_t)2) 
//process-defined behaviour
#define SIG_PROC ((__force __sighandler_t)3)

#define MAGIC 34

static char *config = "";
static char *sigstr[MAGIC] = {
	"SIGHUP",
	"SIGINT",	
	"SIGQUIT",
	"SIGILL",
	"SIGTRAP",
	"SIGABRT",
	"SIGIOT",
	"SIGBUS",
	"SIGFPE",
	"SIGKILL",
	"SIGUSR1",
	"SIGSEGV",
	"SIGUSR2",
	"SIGPIPE",
	"SIGALRM",
	"SIGTERM",
	"SIGSTKFLT",
	"SIGCHLD",
	"SIGCONT",
	"SIGSTOP",
	"SIGTSTP",
	"SIGTTIN",
	"SIGTTOU",
	"SIGURG",
	"SIGXCPU",
	"SIGXFSZ",
	"SIGVTALRM",
	"SIGPROF",
	"SIGWINCH",
	"SIGIO",
	"SIGPOLL",
	"SIGPWR",
	"SIGSYS",
	"SIGRT"
};

static struct tracepoint *signal_deliver_tp = NULL;
struct signal_intercept {
	int sig;
	__sighandler_t sig_handler;
	char *cmd;
};

static struct signal_intercept interceptors[_NSIG] = {0};

/*
 * Copied from kernel/signal.c
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
	struct signal_struct *signal = current->signal;    

	/*
	 * there is no way to receive SIGKILL without a death-signal
	 * so then look for next signal by dequeue_signal	
	 *
	 */

	if(sig == SIGKILL) { 
		signr = select_next_signal(&signal->shared_pending, &current->blocked);
		if(sig_fatal(current,signr) 
				&& interceptors[signr].sig_handler != SIG_PROC){ 
			signr = dequeue_signal(current, &current->blocked, info);
			/*
			 * oh, nice! we've got fatal handled signal and now we should manage
			 * orig signal instead of SIGKILL
			 * 
			 * remove SIGNAL_GROUP_EXIT from signal->flags of process to make
			 * next exit code valid
			 */
			sig = signr;
			signal->flags &= ~SIGNAL_GROUP_EXIT;

			printk(KERN_ALERT "+Signal following by SIKGILL is (%d)", signr);
		}
	}

	printk(KERN_ALERT "+SIG delivered:%d with ka handler %p and action %p", 
			sig, ka->sa.sa_handler, interceptors[sig].sig_handler); //log
	
	switch((unsigned long)interceptors[sig].sig_handler) {
		case (unsigned long)SIG_PROC:
			break;
		case (unsigned long)SIG_DFL:
			printk(KERN_ALERT "+Force default action for (%d)", sig);
			ka->sa.sa_handler = SIG_DFL;
			break;
		case (unsigned long)SIG_USR:
			//do some things 
			printk(KERN_ALERT "+Usr defined handler sig (%d) ", sig);
		case (unsigned long)SIG_IGN:
			printk(KERN_ALERT "+Usr defined handler or ignored sig (%d) ", sig);
			ka->sa.sa_handler = SIG_IGN;
			break;
	}
	/* 
	 * if there was few signals which could kill process 
	 * need to restore SIGKILL and set up valid return code
	 *
	 */
	 
	/* 
	int sign;
	struct sigpending *shared = &signal->shared_pending;
	for(sign = 0; sign < _NSIG; sign++){
		if(sigismember(&shared->signal, sign) && sig_fatal(current, sign)){
			signal->flags = SIGNAL_GROUP_EXIT;                                 
			signal->group_exit_code = sign;                                     
			signal->group_stop_count = 0;                                      

	 	    sigaddset(&shared->signal, SIGKILL);                        
			printk(KERN_DEBUG "+Besides (%d) there was (%d) also.\
					Set up new exit code and SIGNAL_GROUP_EXIT", sig, sign);
			break;
		}
	}
	
		*/
	return;
}

static void find_signal_deliver(struct tracepoint *tp, void *priv) 
{
	if (!strcmp(tp->name, "signal_deliver")){
		signal_deliver_tp = tp;
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

	return 0;
}

//strastr
//counts all needle occurences in haystack

size_t strastr(const char *haystack, const char *needle){
	size_t r = 0;
	char *ptr = haystack;
	while ((ptr = strstr(ptr, haystack)) != NULL){
		r++;
	}
	return r;
}

//TODO: add signature description
size_t prepare_interceptors(char *conf, struct signal_intercept *arr)
{
	char *separator = ";";

	char *space = "<spc>";
	char *semicolon = "<sc>";

	char *SIGIGN = "SIG_IGN";
	char *SIGDFL = "SIG_DFL";

	size_t count = 0;

	char *interceptor;
	char *data;

	//signal delimiter is ; not inside pair of <sh>
	//sig action delimiter is : not inside pair of <sh>
	while((interceptor = strsep(&conf, separator)) != NULL){
		if(strlen(interceptor) == 0){
			break;
		}
		size_t i = 0;
		printk(KERN_ALERT "Int:%s", interceptor);
		while(++i < MAGIC){
			if(!strncmp(sigstr[i], interceptor, strlen(sigstr[i]))){
				printk(KERN_ALERT "Sig %s matched", sigstr[i]);
				count++;
				break;
			}
		}

		if(count == 0){
			break;
		}

		data = strstr(interceptor, ":") + 1;
		printk(KERN_ALERT "Wh: %s", data);
		if(!strncmp(SIGIGN, data, 7)){
			printk(KERN_ALERT "%lu signal now will ignore", i);
			arr[i].sig_handler = SIG_IGN;
			continue;
		}
				
		if(!strncmp(SIGDFL, data, 7)){
			printk(KERN_ALERT "%lu signal now will handle default", i);
			arr[i].sig_handler = SIG_DFL;
			continue;
		}
/*
		//shell-command then
		//replace <spc> and <sc> by " " and ";" and save it pointer to
		//cmd
		size_t command_length = strlen(data) + 1;
		command_length -= strastr(data, "<sc>")+strastr(data, "<spc>");

		char *ptr = kmalloc(command_length * sizeof(char), GFP_KERNEL);

		if(ptr != NULL){
			arr[i].cmd = ptr;
			arr[i].cmd[command_length - 1] = 0;
		} else {
			printk(KERN_ERR "+Kernel memory allocation error. Cannot \
					handle %lu signal", i);
		}

		size_t dest_offset = 0, src_offset = 0;
		while(dest_offset < command_length){
			//find nearest symbol replacement <sc> or <spc>
			char *sc = strstr(data, sc);	
			char *spc = strstr(data, spc);

			char *ptr = data + strlen(data);
	
			if(sc > spc){
				ptr = spc;
			} else {
				ptr = sc;
			}

			strncpy(arr[i].cmd + dest_offset, data + src_offset, ptr - data);

			if(sc > spc){
				dest_offset += ptr - data;
				src_offset += ptr - data + strlen(space);
			} else if(sc < spc){
				dest_offset += ptr - data;
				src_offset += ptr - data + strlen(semicolon);
			} else {
				dest_offset = command_length;
			}
		}
		printk(KERN_INFO "+ Parsed command: %s", arr[i].cmd);
		*/
	}
	


	return count;
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

	size_t ret = prepare_interceptors(config, interceptors);
	printk(KERN_INFO "+%lu intercepters accepted", ret);
	if(!ret)
		return -1; //load module without conf? pfffh
	
	connect_probes();
	return 0;
}

static void __exit unload_module(void) 
{
	if (signal_deliver_tp)
		tracepoint_probe_unregister(signal_deliver_tp,
    signal_deliver_probe, NULL);

	tracepoint_synchronize_unregister();

	//now need to free allocated memory
	int i;

	for(i = 0; i < _NSIG; i++){
		if(interceptors[i].cmd != NULL){
			kfree(interceptors[i].cmd);
		}
	}


	printk(KERN_INFO "+Module unload\n");
}


module_init(load_module);
module_exit(unload_module);
module_param(config, charp, 0000);
MODULE_PARM_DESC(config, "Format for each signal(there is no spaces and \
semi-colons, use <spc> and <sc> instead! \
sig(str):action(SIG_DFL|SIG_IGN|str);");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vladimir iZoomko Gubarev <izoomko@techstories.ru>");
MODULE_DESCRIPTION("signal intercepting");
