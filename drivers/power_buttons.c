#include <linux/module.h>

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>	/* request/free_irq */
#include <linux/ioport.h>	/* check/request/release_region */

#include <asm/io.h>		/* inb, outb */
#include <linux/fs.h>		/* file_operation */
#include <asm/irq.h>		/* enable/disable_irq */
#include <linux/timer.h>	/* timer_list */
#include <linux/delay.h>
#include <linux/mm.h>		/* verify_area */

#include <asm/uaccess.h>	
#include <asm/hardware.h>	
#include <linux/proc_fs.h>


/*
 * ----------------------------------------------------------------------
 * This driver will detect the interrupt when someone push/switch the
 * buttons.
 * Linux will trigger our interrupt function several times when even 
 * though the noise, we have to delay a while to filter the noise.
 * ----------------------------------------------------------------------
 */

/* ---- irq & i/o ---- */
#define BUTTON_POWER_SWITCH 22	/* IRQ */
#define PBUTTON_MAJOR   60 	/* major number */

/*
 * ----------------------------------------------------------------------
 * Debug Message functions: printk(...)
 * ----------------------------------------------------------------------
 */

#ifdef _BUTTON_DEBUG_
#define MYPRINTK(format, argument...) printk(format , ## argument);
#else
#define MYPRINTK(format, argument...)
#endif 

int ok_time;

/*
 * ----------------------------------------------------------------------
 * this function is triggered when the interrupt is triggered.
 * ----------------------------------------------------------------------
 * When this program was called, it means the signal is high - no need
 * to check the i/o.
 * ----------------------------------------------------------------------
 * The interrupt routine won't call itself twice at the same time, keep
 * the stay time as short as possible.
 * ----------------------------------------------------------------------
 */
static void button_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	int i;
	remove_proc_entry("power_off",NULL);
	if (jiffies-ok_time > HZ){
		ok_time=0;
		*IXP425_GPIO_GPOER &= ~0x10;
		for (i=0;i<600;i++){
			*IXP425_GPIO_GPOUTR &= ~(1 << 4);
			udelay(150);
			*IXP425_GPIO_GPOUTR |= 1 << 4;
			udelay(150);
		}
		*IXP425_GPIO_GPOER |= 0x10;
		create_proc_read_entry("power_off",
			0,
			NULL,
			NULL,
			NULL
		);
	}
}

#ifdef MODULE
#define button_init init_module
#endif

int button_init(void)
{
	int ret;

	if (register_chrdev(PBUTTON_MAJOR, "pbuttons", NULL)) {
		MYPRINTK("power button: unable to get major %d\n", PBUTTON_MAJOR);
		return -EIO;
	}
	ok_time=jiffies;
	ret = request_irq(BUTTON_POWER_SWITCH, button_interrupt, SA_INTERRUPT, "pbuttons", NULL);
	if (ret) {
		MYPRINTK("power button: unable to get IRQ %d\n", BUTTON_POWER_SWITCH);
		return -ENXIO;
	} /* end if: regist IRQ */
	enable_irq(BUTTON_POWER_SWITCH);
	return 0;
}

#ifdef MODULE
void cleanup_module(void)
{
	remove_proc_entry("power_off",NULL);
	free_irq(BUTTON_POWER_SWITCH, NULL);        /* release registered irq */
/* ---- Because this driver shared the I/O address with the HD-LED driver,
   we can't occupy the I/O. (Button: read I/O, HDLED: write I/O) ---- */

	unregister_chrdev(PBUTTON_MAJOR, "pbuttons");

	MYPRINTK("power button: cleanup\n");
}
#endif
MODULE_LICENSE("GPL");

