# INTEL-SA-00075-Linux-Detection-And-Mitigation-Tools

## Summary: 
There is an escalation of privilege vulnerability in Intel® Active Management Technology (AMT), Intel® Standard Manageability (ISM), and Intel® Small Business Technology versions firmware versions 6.x, 7.x, 8.x 9.x, 10.x, 11.0, 11.5, and 11.6 that can allow an unprivileged attacker to gain control of the manageability features provided by these products.  This vulnerability does not exist on Intel-based consumer PCs with consumer firmware, Intel servers utilizing Intel® Server Platform Services (Intel® SPS), or Intel® Xeon® Processor E3 and Intel® Xeon® Processor E5 workstations utilizing Intel® SPS firmware.

For general guidance on this issue please see - http://www.intel.com/content/www/us/en/architecture-and-technology/intel-amt-vulnerability-announcement.html 

As Intel becomes aware of computer maker schedules for updated firmware this list will be updated:

HP Inc. - http://www8.hp.com/us/en/intelmanageabilityissue.html
HP Enterprise - http://h22208.www2.hpe.com/eginfolib/securityalerts/CVE-2017-5689-Intel/CVE-2017-5689.html
Lenovo - https://support.lenovo.com/us/en/product_security/LEN-14963
Fujitsu - http://www.fmworld.net/globalpc/intel_firmware/
Dell Client - http://en.community.dell.com/techcenter/extras/m/white_papers/20443914
Dell EMC - http://en.community.dell.com/techcenter/extras/m/white_papers/20443937
Acer -  https://us.answers.acer.com/app/answers/detail/a_id/47605 
Asus - https://www.asus.com/News/uztEkib4zFMHCn5r
Panasonic - http://pc-dl.panasonic.co.jp/itn/info/osinfo20170512.html
Toshiba - https://support.toshiba.com/sscontent?contentId=4015668
Getac - http://intl.getac.com/aboutgetac/activities/activities_2017051648.html
Intel – NUC, Compute Stick and Desktop Boards
Samsung - http://www.samsung.com/uk/support/intel_update/

## Description: 
There are two ways this vulnerability may be accessed please note that Intel® Small Business Technology is not vulnerable to the first issue.

An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel® Active Management Technology (AMT) and Intel® Standard Manageability (ISM).
CVSSv3 9.8 Critical /AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel® Active Management Technology (AMT), Intel® Standard Manageability (ISM), and Intel® Small Business Technology (SBT).
CVSSv3 8.4 High /AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Affected products: 
The issue has been observed in Intel manageability firmware versions 6.x, 7.x, 8.x 9.x, 10.x, 11.0, 11.5, and 11.6 for Intel® Active Management Technology, Intel® Small Business Technology, and Intel® Standard Manageability.  Versions before 6 or after 11.6 are not impacted.

## Recommendations: 
Intel has released a downloadable discovery tool located at downloadcenter.intel.com, which will analyze your system for the vulnerability. IT professionals who are familiar with the configuration of their systems and networks can use this tool or can find more details below.

Step 1: Determine if you have an Intel® AMT, Intel® SBA, or Intel® ISM capable system.  If you determine that you do not have an Intel® AMT, Intel® SBA, or Intel® ISM capable system then no further action is required.

Step 2: Utilize the INTEL-SA-00075 Detection Guide to assess if your system has the impacted firmware. If you do have a version in the “Resolved Firmware” column no further action is required to secure your system from this vulnerability.
Linux users use the INTEL-SA-00075-Discovery-Tool  on this github page. For documentation and release binaries please visit https://downloadcenter.intel.com/download/26799/INTEL-SA-00075-Linux-Detection-and-Mitigation-Tools

Step 3: Intel highly recommends checking with your system OEM for updated firmware.  Firmware versions that resolve the issue have a four digit build number that starts with a “3” (X.X.XX.3XXX) Ex: 8.1.71.3608.
Firmware Deployment Guide at http://www.intel.com/content/www/us/en/support/technologies/intel-active-management-technology-intel-amt/000024236.html

Step 4: If a firmware update is not available from your OEM, mitigations are provided the INTEL-SA-00075 Mitigation Guide.
Linux users use the INTEL-SA-00075-Unprovisioning-Tool on this github page.
For assistance in implementing the mitigations steps provided in this document, please contact Intel Customer Support at http://www.intel.com/content/www/us/en/support/contact-support.html#@23; from the Technologies section, select Intel® Active Management Technology (Intel® AMT).


## Build instructions for the INTEL-SA-00075-Discovery-Tool and INTEL-SA-00075-Unprovisioning-Tool

make clean; make
sudo ./INTEL-SA-00075-Discovery-Tool or sudo ./INTEL-SA-00075-Discovery-Tool -d /dev/mei
sudo ./INTEL-SA-00075-Unprovisioning-Tool or sudo ./INTEL-SA-00075-Unprovisioning-Tool -d /dev/mei

NOTE: 
If mei device /dev/mei0 is not found, Open Terminal and list available devices with ls /dev/mei*
This should give the proper device node /dev/mei# ; then re-run the application with correct node
e.g sudo ./ INTEL-SA-00075-Unprovisioning-Tool –d /dev/mei0
This tool requires MEI support from the running kernel (in recent kernels that is CONFIG_INTEL_MEI and CONFIG_INTEL_MEI_ME under Device Drivers|Misc devices)
WARNING: Being unable to access /dev/mei0 does NOT imply that this system has no MEI support and may be still vulnerable.

