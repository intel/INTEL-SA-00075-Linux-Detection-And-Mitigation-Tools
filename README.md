# INTEL-SA-00075-Linux-Detection-And-Mitigation-Tools

Latest Release @ https://downloadcenter.intel.com/download/26799/INTEL-SA-00075-Linux-Detection-and-Mitigation-Tools

make

sudo ./INTEL-SA-00075-Discovery-Tool or sudo ./INTEL-SA-00075-Discovery-Tool -d /dev/mei

sudo ./INTEL-SA-00075-Unprovisioning-Tool or sudo ./INTEL-SA-00075-Unprovisioning-Tool -d /dev/mei

NOTE: 
If mei device is not found, Open Terminal and list available devices
ls /dev/mei*
This shoudl give the proper device node /dev/mei# ; then re-run the application with correct node
e.g sudo ./ INTEL-SA-00075-Unprovisioning-Tool –d /dev/mei0
