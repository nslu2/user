#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>	/* request/free_irq */
#include <asm/irq.h>		/* enable/disable_irq */
#include <linux/delay.h>
#include <asm/uaccess.h>	
#include <asm/hardware.h>	




/*
 * ----------------------------------------------------------------------
 * This driver will detect the interrupt when someone push/switch the
 * buttons.
 * Linux will trigger our interrupt function several times when even 
 * though the noise, we have to delay a while to filter the noise.
 * ----------------------------------------------------------------------
 */
static int r_flag;

DECLARE_WAIT_QUEUE_HEAD(reset_button_wait);

#define BUTTON_RESET_SWITCH 29	/* IRQ */
#define RBUTTON_MAJOR   61 	/* major number */
//#define BUTTON_MINOR    3	/* minor number: 3 buttons */
#define RESET_IP_MSG		"reset_ip"
#define RESET_PASSWD_MSG	"reset_pw"


/*
 * ----------------------------------------------------------------------
 * Debug Message functions: printk(...)
 * ----------------------------------------------------------------------
 */

static int r_ok_time;

void my_beep(void)
{
	int i;
	
	*IXP425_GPIO_GPOER &= ~0x10;
	for (i=0;i<600;i++){
		*IXP425_GPIO_GPOUTR &= ~(1 << 4);
		udelay(150);
		*IXP425_GPIO_GPOUTR |= 1 << 4;
		udelay(150);
	}
	*IXP425_GPIO_GPOER |= 0x10;
}

static void bt_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	int times=0;
//	r_flag=3;
        wake_up_interruptible(&reset_button_wait);

	if (jiffies-r_ok_time > 2*HZ){
		while(!(*IXP425_GPIO_GPINR & 0x1000)){
			mdelay(100);
			times ++;
			if (times >= 100){
			//reset passwd
				r_flag=0;
				my_beep();
				r_ok_time=jiffies;
				return;
			}
		}
		r_flag=1;//reset ip
		r_ok_time=jiffies;

		//beep one time
		my_beep();
	}
}

int bt_open(struct inode * inode, struct file * file)
{
	return 0;
}

int bt_release(struct inode * inode, struct file * file)
{
	return 0;
}

ssize_t bt_read(struct file * node, char *buf, size_t count, loff_t *off)
{
	interruptible_sleep_on(&reset_button_wait);
	/* arrived when wakes up */
	switch(r_flag){
		case 0:
		copy_to_user(buf,RESET_PASSWD_MSG, strlen(RESET_PASSWD_MSG));
			r_flag=3;
		return strlen(RESET_PASSWD_MSG);
		case 1:
		copy_to_user(buf, RESET_IP_MSG, strlen(RESET_IP_MSG));
			r_flag=3;
		return strlen(RESET_IP_MSG);
		default:
			copy_to_user(buf, "  ", 2);
			return 2;
			
	}
}

/*
 * ----------------------------------------------------------------------
 * Module initial and free function
 * ----------------------------------------------------------------------
 */


static struct file_operations bt_fops = {
	read:        bt_read,    /* read */
	open:        bt_open,    /* open */
	release:     bt_release, /* release */
};

#ifdef MODULE
#define bt_init init_module
#endif

int bt_init(void)
{
	int ret;
	if (register_chrdev(RBUTTON_MAJOR, "rbuttons", &bt_fops)) {
		printk("reset button: unable to get major %d\n", RBUTTON_MAJOR);
		return -EIO;
	}
	r_ok_time=jiffies;
	ret = request_irq(BUTTON_RESET_SWITCH, bt_interrupt, SA_INTERRUPT, "rbuttons", NULL);
	if (ret) {
		printk("reset button: unable to get IRQ %d\n", BUTTON_RESET_SWITCH);
		return -ENXIO;
	} /* end if: regist IRQ */
	return 0;
}

#ifdef MODULE
void cleanup_module(void)
{
	free_irq(BUTTON_RESET_SWITCH, NULL);        /* release registered irq */
/* ---- Because this driver shared the I/O address with the HD-LED driver,
   we can't occupy the I/O. (Button: read I/O, HDLED: write I/O) ---- */

	unregister_chrdev(RBUTTON_MAJOR, "rbuttons");

}
#endif
MODULE_LICENSE("GPL");

