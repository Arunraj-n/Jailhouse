/*
 *  Driver core for virtual serial ports
 *
 *  Based on drivers/char/serial.c, by Linus Torvalds, Theodore Ts'o.
 *
 *  Copyright 1999 ARM Limited
 *  Copyright (C) 2000-2001 Deep Blue Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/of.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/device.h>
#include <linux/serial.h> /* for serial_state and serial_icounter_struct */
#include <linux/serial_core.h>
#include <linux/delay.h>
#include <linux/mutex.h>


//#include <linux/serial_8250.h>

#include <linux/irq.h>
#include <linux/uaccess.h>

#define VIRCON_SHARED 1

#include <linux/timer.h>
#include <linux/jiffies.h>

#define VIRTUAL_UART_WRITE_ROOM_BUF 4095

#if VIRCON_SHARED
//#define DRAM_SHARED_MEM 	/*0x3f201000*/ 0x3f200000
//#define DRAM_SHARED_MEM_SIZE  	0x1000 //place the size here

#define DRAM_SHARED_MEM_SIZE_TX  0xF00 /*0xFFE00*/ // place the size here
#define DRAM_SHARED_MEM_SIZE_RX  0xF8  /*0x100*/   //(DRAM_SHARED_MEM+DRAM_SHARED_MEM_SIZE_TX)
#define DRAM_SHARED_MEM_OFFSET_RX  DRAM_SHARED_MEM_SIZE_TX


#define SYNC_POINTER_OFFSET (DRAM_SHARED_MEM_SIZE_TX+DRAM_SHARED_MEM_SIZE_RX) //0x6000
#define WRITE_PTR_OFFSET SYNC_POINTER_OFFSET 
#define READ_PTR_OFFSET (SYNC_POINTER_OFFSET+4)

static unsigned long int dram_shared_mem;
static unsigned long int dram_shared_mem_size;

static volatile unsigned char *shared_mem_tx;
static volatile unsigned char *shared_mem_rx;
static volatile unsigned int *shared_mem_tx_ptr =0 ;
static volatile unsigned int *shared_mem_rx_ptr =0 ;

static unsigned int local_write_ptr = 0;
static unsigned int local_read_ptr = 0;
static unsigned int shared_mem_init_done = 0;
static struct tty_port **shared_mem_port;
static int console_index = 0;
unsigned char virt_shared_char[] = "hyp";

void virt_periodic_poll_rx(unsigned long data);
int virt_g_time_interval = 1000;
struct timer_list virt_g_timer_shared_mem;
DEFINE_TIMER(virt_g_timer_shared_mem, virt_periodic_poll_rx,0,0);
#endif


static int virtual_uart_write(struct tty_struct *tty,
					const unsigned char *buf, int count)
{
	int i, ret = 0;

#if VIRCON_SHARED 
        for(i=0; i<count; i++)
	{
		*(shared_mem_tx + local_write_ptr) = *(buf+i);
		local_write_ptr = local_write_ptr + 1;
		if(local_write_ptr == DRAM_SHARED_MEM_SIZE_TX)
			local_write_ptr=0;
	}
	*(shared_mem_tx_ptr) = local_write_ptr;
#endif

	return count;
}

static int virtual_uart_write_room(struct tty_struct *tty)
{
	return VIRTUAL_UART_WRITE_ROOM_BUF;

}



/*
 * Called via sys_ioctl.  We can use spin_lock_irq() here.
 */
static int
virtual_uart_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
{

	return 0;
}
/*
 * Calls to uart_close() are serialised via the tty_lock in
 *   drivers/tty/tty_io.c:tty_release()
 *   drivers/tty/tty_io.c:do_tty_hangup()
 */
static void virtual_uart_close(struct tty_struct *tty, struct file *filp)
{
	/*Just return the control for this virtual uart*/
	return;
}


/*
	virtual uart open called when the tty driver is opened.
        virtual uart doesn't have any specfic port initialization.
	So just return the control to the virtual uart. 

*/
static int virtual_uart_open(struct tty_struct *tty, struct file *filp)
{
	int retval = 0;
	return retval;
}


static void shared_mem(unsigned char ch)
{
	unsigned int i;
	
	if(shared_mem_init_done == 0)
	{
		get_shared_mem_addr(&dram_shared_mem,&dram_shared_mem_size);
		
		void __iomem *shared_virt = ioremap(dram_shared_mem,
							dram_shared_mem_size);
		
		//void __iomem *shared_virt = ioremap(DRAM_SHARED_MEM, DRAM_SHARED_MEM_SIZE);
		//volatile char *shared_mem = (char *)shared_virt;
		
		shared_mem_tx = (char *)shared_virt;
		//for(i=0; i<DRAM_SHARED_MEM_SIZE; i++)
		for(i=0; i<dram_shared_mem_size; i++)
			shared_mem_tx[i] = 0;
		
		shared_mem_rx = (char *)(shared_virt+ DRAM_SHARED_MEM_OFFSET_RX);
		shared_mem_tx_ptr = (unsigned int *)(shared_virt+ WRITE_PTR_OFFSET);
		shared_mem_rx_ptr = (unsigned int *)(shared_virt+ READ_PTR_OFFSET);

		shared_mem_init_done =1;
	}

	*(shared_mem_tx + local_write_ptr) = ch;
	local_write_ptr = local_write_ptr + 1;
	if(local_write_ptr == DRAM_SHARED_MEM_SIZE_TX)
		local_write_ptr=0;
	*(shared_mem_tx_ptr) = local_write_ptr;
}


void virtual_console_write(const char *s,unsigned int count)
{
	unsigned int i;
		
	for (i = 0; i < count; i++, s++) {
		if (*s == '\n')
		{
			shared_mem('\r');
		}

		shared_mem(*s);
	}
}
EXPORT_SYMBOL_GPL(virtual_console_write);

struct tty_driver *virtual_uart_console(struct console *co, int *index)
{
        struct uart_driver *p = co->data; 
	
	p->tty_driver->ports[co->index] = shared_mem_port[co->index];	

	console_index = co->index;
        *index = co->index;
        return p->tty_driver;
}



static const struct tty_operations uart_ops = {
	.open		= virtual_uart_open,
	.close		= virtual_uart_close,
	.write		= virtual_uart_write,
	.write_room	= virtual_uart_write_room,
	.ioctl		= virtual_uart_ioctl,
};

/*static const struct tty_port_operations null_port_ops = {
};*/

/**
 *	uart_register_driver - register a driver with the uart core layer
 *	@drv: low level driver structure
 *
 *	Register a uart driver with the core driver.  We in turn register
 *	with the tty layer, and initialise the core driver per-port state.
 *
 *	We have a proc file in /proc/tty/driver which is named after the
 *	normal driver.
 *
 *	drv->port should be NULL, and the per-port structures should be
 *	registered using uart_add_one_port after this call has succeeded.
 */

int virtual_uart_register_driver(struct uart_driver *drv)
{
	struct tty_driver *normal;
	int i, retval;
	BUG_ON(drv->state);

	mod_timer(&virt_g_timer_shared_mem, jiffies + msecs_to_jiffies(virt_g_time_interval));

	/*
	 * Maybe we should be using a slab cache for this, especially if
	 * we have a large number of ports to handle.
	 */
	drv->state = kzalloc(sizeof(struct uart_state) * drv->nr, GFP_KERNEL);
	if (!drv->state)
		goto out;

	normal = alloc_tty_driver(drv->nr);
	if (!normal)
		goto out_kfree;

	drv->tty_driver = normal;

	shared_mem_port = (struct tty_port **)kmalloc(drv->nr *
                                         sizeof(struct tty_port*), GFP_KERNEL);
	for(i=0; i<(drv->nr); i++)
        {
                shared_mem_port[i] = kmalloc(sizeof(struct tty_port),
                                                GFP_KERNEL);
        }



	normal->driver_name	= drv->driver_name;
	normal->name		= drv->dev_name;
	normal->major		= drv->major;
	normal->minor_start	= drv->minor;
	normal->type		= TTY_DRIVER_TYPE_SERIAL;
	normal->subtype		= SERIAL_TYPE_NORMAL;
	normal->init_termios	= tty_std_termios;
	normal->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
	normal->init_termios.c_ispeed = normal->init_termios.c_ospeed = 9600;
	normal->flags		= TTY_DRIVER_REAL_RAW | TTY_DRIVER_DYNAMIC_DEV;
	normal->driver_state    = drv;
	tty_set_operations(normal, &uart_ops);

	/*
	 * Initialise the UART state(s).
	 */
	for (i = 0; i < drv->nr; i++) {
		struct uart_state *state = drv->state + i;
		struct tty_port *port = &state->port;

		tty_port_init(port);
		shared_mem_port[i] = port;
		port->ops = NULL;
	}

	retval = tty_register_driver(normal);
	if (retval >= 0)
		return retval;

	for (i = 0; i < drv->nr; i++)
		tty_port_destroy(&drv->state[i].port);
	put_tty_driver(normal);
out_kfree:
	kfree(drv->state);
out:
	return -ENOMEM;
}

/**
 *	uart_unregister_driver - remove a driver from the uart core layer
 *	@drv: low level driver structure
 *
 *	Remove all references to a driver from the core driver.  The low
 *	level driver must have removed all its ports via the
 *	uart_remove_one_port() if it registered them with uart_add_one_port().
 *	(ie, drv->port == NULL)
 */
void virtual_uart_unregister_driver(struct uart_driver *drv)
{
	struct tty_driver *p = drv->tty_driver;
	unsigned int i;

	del_timer(&virt_g_timer_shared_mem);

	tty_unregister_driver(p);
	put_tty_driver(p);
	for (i = 0; i < drv->nr; i++)
		tty_port_destroy(&drv->state[i].port);
	kfree(drv->state);
	drv->state = NULL;
	drv->tty_driver = NULL;
}


void virt_periodic_poll_rx(unsigned long data)
{
	int i;
	unsigned char ch;	
	int num_char_to_read = 0;
	int shared_mem_current_loc =*(shared_mem_rx_ptr);
	if (local_read_ptr > shared_mem_current_loc)
	{
		num_char_to_read = (DRAM_SHARED_MEM_SIZE_RX - local_read_ptr)+ shared_mem_current_loc;	
	}
	else
	num_char_to_read = shared_mem_current_loc - local_read_ptr;
	
	//printk("\nperiodic_poll_rx shared ptr :%d \t local:%d\n",shared_mem_current_loc,local_read_ptr);

	for(i=0; i<num_char_to_read ; i++)
	{
		ch = *(shared_mem_rx + local_read_ptr);
		local_read_ptr = local_read_ptr + 1;
		if(local_read_ptr == DRAM_SHARED_MEM_SIZE_RX)
			local_read_ptr = 0;
		if (tty_insert_flip_char(shared_mem_port[console_index], ch, TTY_NORMAL) == 0)
			printk("ERROR\n");
		tty_flip_buffer_push(shared_mem_port[console_index]);
	}
	mod_timer(&virt_g_timer_shared_mem, jiffies + msecs_to_jiffies(virt_g_time_interval));
}




EXPORT_SYMBOL(virtual_uart_register_driver);
EXPORT_SYMBOL(virtual_uart_unregister_driver);

MODULE_DESCRIPTION("Virtual Serial driver core");
MODULE_LICENSE("GPL");
