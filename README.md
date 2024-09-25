# PTPD master and slave projects with Power Profile support for ST NUCLEO-F429ZI

This code implements IEEE1588-2008 PTP protocol with Power Profile on STM32F429ZI microcontroller.
It improves previous versions of PTP projects for STM32 in several ways:

 - Provides support of PTP Power Profile (PTP messages are transported over IEEE 802.3 / Ethernet - 
 L2 layer of OSI model).
 - Using Power Profile allows to reach synchronization accuracy of ±100 nsec offset between
 master and slave clocks.
 - Improves synchronization accuracy when using default profile (Transport of PTP messages over UDP/IP): 
 offset between master and slave is reduced down to ±500 nsec.
 - Fixes Peer delay mechanism of PTP (P2P mode).
 - Configures the 1PPS signal on PB5 pin of the MCU (can be turned off in ptpd_init function).

## Power Profile configuration

To turn on the Power Profile support, uncomment the "#define PTPD_POWER_PROFILE" line
in ptpd.h file. After that all PTP messages will be sent and received over L2 layer of OSI model.

## Experimental study

The functionality of the master and slave projects was tested using two NUCLEO-F429ZI 
development boards connected to each other via Ethernet in a local network through a 
TP-Link TL-WR842N switch. The Power Profile support was turned on and devices used 
peer delay mechanism of synchronization. To verify the synchronization of 
the internal clocks of two boards, 1PPS signals were output from each board. 
The signals were captured using a RIGOL MSO2302 oscilloscope.

![Screenshot](https://github.com/AkhtyrskiyKirill/STM32-PTPd-Power-Profile/blob/main/imgs/1PPS_PowerProfile.png)

The results of multiple experiments showed that the rising edges of the 1PPS signals on the 
two devices were synchronized with an accuracy of no worse than ±100 ns.

## Contact information

Authors of the project:  
Akhtyrskiy Kirill  
Kabirov Vagiz  
Semenov Valerii

If you want to contribute to the improvement and development of the project please 
send comments, feature requests, bug reports, or patches.

Contact email: k.akhtirsky@gmail.com
