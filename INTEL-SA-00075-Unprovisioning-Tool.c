/******************************************************************************
 * Intel-SA-00075-Unprovisioning-Tool
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright (C) 2003-2012, 2017 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *	Intel Corporation.
 *	linux-mei@linux.intel.com
 *	http://www.intel.com
 *
 * BSD LICENSE
 *
 * Copyright (C) 2003-2012, 2017 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <bits/wordsize.h>
#include <linux/mei.h>

/*****************************************************************************
 * Intel(R) MEI
 *****************************************************************************/

#define mei_msg(_me, fmt, ARGS...) do {         \
	if (_me->verbose)                       \
		fprintf(stderr, fmt, ##ARGS);	\
} while (0)

#define mei_err(_me, fmt, ARGS...) do {         \
	fprintf(stderr, "Error: " fmt, ##ARGS); \
} while (0)

struct mei {
    uuid_le guid;
    bool initialized;
    bool verbose;
    unsigned int buf_size;
    unsigned char prot_ver;
    int fd;
};

static void mei_deinit(struct mei *cl) {
    if (cl->fd != -1) {
        close(cl->fd);
    }
    cl->fd = -1;
    cl->buf_size = 0;
    cl->prot_ver = 0;
    cl->initialized = false;
}

#define MAX_DEV_NODE_PATH 12
char *dev_path;
bool custom_dev_node = false;
static bool mei_init(struct mei *me, const uuid_le *guid,
        unsigned char req_protocol_version, bool verbose) {
    int result;
    struct mei_client *cl;
    struct mei_connect_client_data data;

    me->verbose = verbose;

    if (custom_dev_node) {
        me->fd = open(dev_path, O_RDWR);
    } else {
        me->fd = open("/dev/mei0", O_RDWR);
    }
    if (me->fd == -1) {
        if (!geteuid()) {
            mei_err(me, "Cannot establish a handle to the Intel(R) MEI driver. Contact OEM.\n");
            exit(-1);
        } else {
            mei_err(me, "Please run the tool with root privilege.\n");
            mei_deinit(me);
            exit(-1);
        }
        goto err;
    }
    memcpy(&me->guid, guid, sizeof(*guid));
    memset(&data, 0, sizeof(data));
    me->initialized = true;

    memcpy(&data.in_client_uuid, &me->guid, sizeof(me->guid));
    result = ioctl(me->fd, IOCTL_MEI_CONNECT_CLIENT, &data);
    if (result) {
        mei_err(me, "IOCTL_MEI_CONNECT_CLIENT receive message. err=%d\n",
                result);
        goto err;
    }
    cl = &data.out_client_properties;
    mei_msg(me, "max_message_length %d\n", cl->max_msg_length);
    mei_msg(me, "protocol_version %d\n", cl->protocol_version);

    if ((req_protocol_version > 0)
            && (cl->protocol_version != req_protocol_version)) {
        mei_err(me, "Intel(R) MEI protocol version not supported\n");
        goto err;
    }

    me->buf_size = cl->max_msg_length;
    me->prot_ver = cl->protocol_version;

    return true;
    err: mei_deinit(me);
    return false;
}

static ssize_t mei_recv_msg(struct mei *me, unsigned char *buffer, ssize_t len,
        unsigned long timeout) {
    ssize_t rc;

    mei_msg(me, "call read length = %zd\n", len);

    rc = read(me->fd, buffer, len);
    if (rc < 0) {
        mei_err(me, "read failed with status %zd %s\n", rc, strerror(errno));
        mei_deinit(me);
    } else {
        mei_msg(me, "read succeeded with result %zd\n", rc);
    }
    return rc;
}

static ssize_t mei_send_msg(struct mei *me, const unsigned char *buffer,
        ssize_t len, unsigned long timeout) {
    struct timeval tv;
    ssize_t written;
    ssize_t rc;
    fd_set set;

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000000;

    mei_msg(me, "call write length = %zd\n", len);

    written = write(me->fd, buffer, len);
    if (written < 0) {
        rc = -errno;
        mei_err(me, "write failed with status %zd %s\n", written,
                strerror(errno));
        goto out;
    }

    FD_ZERO(&set);
    FD_SET(me->fd, &set);
    rc = select(me->fd + 1, &set, NULL, NULL, &tv);
    if (rc > 0 && FD_ISSET(me->fd, &set)) {
        mei_msg(me, "write success\n");
    } else if (rc == 0) {
        mei_err(me, "write failed on timeout with status\n");
        goto out;
    } else {
        mei_err(me, "write failed on select with status %zd\n", rc);
        goto out;
    }

    rc = written;
    out: if (rc < 0) {
        mei_deinit(me);
    }

    return rc;
}

/***************************************************************************
 * Intel(R) AMT - Client
 ***************************************************************************/
const uuid_le MEI_IAMTHIF = UUID_LE(0x12f80028, 0xb4b7, 0x4b2d, 0xac, 0xa8,
        0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c);

#define AMT_MAJOR_VERSION 1
#define AMT_MINOR_VERSION 1

#define AMT_STATUS_SUCCESS                0x0
#define AMT_STATUS_INTERNAL_ERROR         0x1
#define AMT_STATUS_NOT_READY              0x2
#define AMT_STATUS_INVALID_AMT_MODE       0x3
#define AMT_STATUS_INVALID_MESSAGE_LENGTH 0x4

typedef enum {
    AMT_STATUS_TABLE_FINGERPRINT_NOT_AVAILABLE = 5,
    AMT_STATUS_INTEGRITY_CHECK_FAILED = 6,
    AMT_STATUS_UNSUPPORTED_ISVS_VERSION = 7,
    AMT_STATUS_INVALID_REGISTRATION_DATA = 9,
    AMT_STATUS_APPLICATION_DOES_NOT_EXIST = 10,
} AMT_STATUS;

typedef enum {
    CFG_UNPROVISIONING_STATE_NONE = 0, CFG_UNPROVISIONING_STATE_IN = 1,
} CFG_UNPROVISIONING_STATE;

typedef struct {
    uint32_t Operation :23;
    uint32_t IsResponse :1;
    uint32_t Class :8;
} COMMAND_FMT;

typedef struct {
    uint8_t MajorNumber;
    uint8_t MinorNumber;
} PTHI_VERSION;

typedef struct {
    PTHI_VERSION Version;
    uint16_t Reserved;
    COMMAND_FMT Command;
    uint32_t Length;
} PTHI_MESSAGE_HEADER;

struct amt_host_if {
    struct mei mei_cl;
    unsigned long send_timeout;
    bool initialized;
};

static bool amt_host_if_init(struct amt_host_if *acmd,
        unsigned long send_timeout, bool verbose) {
    acmd->send_timeout = (send_timeout) ? send_timeout : 20000;
    acmd->initialized = mei_init(&acmd->mei_cl, &MEI_IAMTHIF, 0, verbose);
    return acmd->initialized;
}

/*****************************************************************************
 * Check Provisioned State
 *****************************************************************************/
#define PROVISIONING_STATE_PRE 0
#define PROVISIONING_STATE_IN 1
#define PROVISIONING_STATE_POST 2

typedef struct {
    PTHI_MESSAGE_HEADER Header;
} CFG_GetProvisioningState_Request;

typedef struct {
    PTHI_MESSAGE_HEADER Header;
    uint32_t Status;
    uint32_t ProvisioningState;
} CFG_GetProvisioningState_Response;

int check_amt_provision_status(void) {
    struct amt_host_if acmd;
    int rval = 0;

    if (!amt_host_if_init(&acmd, 5000, false)) {
        printf("Error: Failed Unprovisioning. Use Intel(R) MEBX to unprovision. Or Contact OEM\n");
        rval = -1;
        goto failed_check_amt_provision_status;
    }

    CFG_GetProvisioningState_Request request = {
            .Header.Version.MajorNumber = 1, .Header.Version.MinorNumber = 1,
            .Header.Command.Class = 4, .Header.Command.Operation = 0x11,
            .Header.Length = sizeof(request.Header) };

    uint32_t written = mei_send_msg(&acmd.mei_cl,
            (const unsigned char *) &request, sizeof(request),
            acmd.send_timeout);
    if (written != sizeof(request)) {
        rval = -1;
        goto failed_check_amt_provision_status;
    }

    CFG_GetProvisioningState_Response response;
    uint32_t out_buf_sz = mei_recv_msg(&acmd.mei_cl,
            (unsigned char *) &response, sizeof(response), 2000);
    if (out_buf_sz <= 0 || response.Status != AMT_STATUS_SUCCESS) {
        rval = -1;
        goto failed_check_amt_provision_status;
    } else {
        if (response.ProvisioningState == PROVISIONING_STATE_IN
                || response.ProvisioningState == PROVISIONING_STATE_POST) {
            rval = 1;
        }
    }

    failed_check_amt_provision_status: mei_deinit(&acmd.mei_cl);
    acmd.initialized = false;
    return rval;
}

/*****************************************************************************
 * Check UnProvisioning State
 *****************************************************************************/

typedef struct {
    PTHI_MESSAGE_HEADER Header;
} CFG_GetUnprovisioningState_Request;

typedef struct {
    PTHI_MESSAGE_HEADER Header;
    AMT_STATUS Status;
    CFG_UNPROVISIONING_STATE State;  // returned upon success only
} CFG_GetUnprovisioningState_Response;

int check_amt_unprovisioning_status(void) {
    struct amt_host_if acmd;
    int rval = 0;

    if (!amt_host_if_init(&acmd, 5000, false)) {
        printf("Error: Failed Unprovisioning. Use Intel(R) MEBX to unprovision. Or Contact OEM\n");
        rval = -1;
        goto failed_check_amt_unprovisioning_status;
    }

    CFG_GetUnprovisioningState_Request request = { .Header.Version.MajorNumber =
            1, .Header.Version.MinorNumber = 1, .Header.Command.Class = 4,
            .Header.Command.Operation = 0x68, .Header.Length =
                    sizeof(request.Header) };

    uint32_t written = mei_send_msg(&acmd.mei_cl,
            (const unsigned char *) &request, sizeof(request),
            acmd.send_timeout);
    if (written != sizeof(request)) {
        rval = -1;
        goto failed_check_amt_unprovisioning_status;
    }

    CFG_GetUnprovisioningState_Response response;
    uint32_t out_buf_sz = mei_recv_msg(&acmd.mei_cl,
            (unsigned char *) &response, sizeof(response), 2000);
    if (out_buf_sz <= 0 || response.Status != AMT_STATUS_SUCCESS) {
        rval = -1;
        goto failed_check_amt_unprovisioning_status;
    } else {
        if (!response.State) {
            printf("System needs to be unprovisioned.\n");
        } else {
            printf("System is already unprovisioned.\n");
        }
    }

    failed_check_amt_unprovisioning_status: 
    mei_deinit(&acmd.mei_cl);
    acmd.initialized = false;
    return rval;
}


/*****************************************************************************
 * Check Provisioning Control Mode
 *****************************************************************************/
typedef struct
{
    PTHI_MESSAGE_HEADER                Header;
}  CFG_GetControlMode_Request;

typedef struct
{
    PTHI_MESSAGE_HEADER Header;
    uint32_t Status;
    uint32_t ControlMode;  // returned upon success only
}  CFG_GetControlMode_Response;

int get_provisioning_control_mode(void) {
    struct amt_host_if acmd;
    int rval = 0;
    if (!amt_host_if_init(&acmd, 5000, false)) {
        rval = -1;
        goto failed_get_provisioning_control_mode;
    }

    CFG_GetControlMode_Request request = {
        .Header.Version.MajorNumber = 1, 
        .Header.Version.MinorNumber = 1,
        .Header.Command.Class = 0x4, 
        .Header.Command.Operation = 0x6B,
        .Header.Length = sizeof(request.Header) 
    };

    uint32_t written = mei_send_msg(&acmd.mei_cl,
            (const unsigned char *) &request, sizeof(request),
            acmd.send_timeout);
    if (written != sizeof(request)) {
        rval = -1;
        goto failed_get_provisioning_control_mode;
    }

    CFG_GetControlMode_Response response;
    uint32_t out_buf_sz = mei_recv_msg(&acmd.mei_cl,
            (unsigned char *) &response, sizeof(response), 2000);
    if (out_buf_sz <= 0 || response.Status != AMT_STATUS_SUCCESS) {
        rval = -1;
        goto failed_get_provisioning_control_mode;
    } else {
        rval = response.ControlMode;
    }
    failed_get_provisioning_control_mode: 
    mei_deinit(&acmd.mei_cl);
    acmd.initialized = false;
    return rval;
}


/*****************************************************************************
 * CCM UNPROVISION COMMAND
 *****************************************************************************/
typedef enum {
    CFG_PROVISIONING_MODE_NONE = 0,
    CFG_PROVISIONING_MODE_ENTERPRISE = 1,
    CFG_PROVISIONING_MODE_SMALL_BUSINESS = 2,
    CFG_PROVISIONING_MODE_REMOTE_CONNECTIVITY_SERVICE = 3,
} CFG_PROVISIONING_MODE;

typedef struct {
    PTHI_MESSAGE_HEADER Header;
    CFG_PROVISIONING_MODE Mode;
} CFG_Unprovision_Request;

typedef struct {
    PTHI_MESSAGE_HEADER Header;
    AMT_STATUS Status;
} CFG_Unprovision_Response;

int un_provision_amt_ccm(void) {
    struct amt_host_if acmd;
    int rval = 0;
    CFG_PROVISIONING_MODE mode = CFG_PROVISIONING_MODE_NONE;

    if (!amt_host_if_init(&acmd, 5000, false)) {
        printf("Error: Failed Unprovisioning. Use Intel(R) MEBX to unprovision. Or Contact OEM\n");
        rval = -1;
        goto failed_un_provision_amt_ccm;
    }

    CFG_Unprovision_Request request = { .Header.Version.MajorNumber =
    AMT_MAJOR_VERSION, .Header.Version.MinorNumber = AMT_MINOR_VERSION,
            .Header.Command.Class = 4, .Header.Command.Operation = 0x10, .Mode =
                    mode, .Header.Length = sizeof(request.Header) };

    uint32_t written = mei_send_msg(&acmd.mei_cl,
            (const unsigned char *) &request, sizeof(request),
            acmd.send_timeout);
    if (written != sizeof(request)) {
        printf("Error: Failed Unprovisioning. Use Intel(R) MEBX to unprovision. Or Contact OEM\n");
        rval = -1;
        goto failed_un_provision_amt_ccm;
    }

    CFG_Unprovision_Response response;
    uint32_t out_buf_sz = mei_recv_msg(&acmd.mei_cl,
            (unsigned char *) &response, sizeof(response), 2000);
    if (out_buf_sz <= 0 || response.Status != AMT_STATUS_SUCCESS) {
            printf("Error: Failed Unprovisioning. Use Intel(R) MEBX to unprovision. Or Contact OEM: %d\n",
                    response.Status);
        rval = -1;
        goto failed_un_provision_amt_ccm;
    } else {
        printf("\tSuccessfully Unprovisioned.\n");
    }

    failed_un_provision_amt_ccm: 
    mei_deinit(&acmd.mei_cl);
    acmd.initialized = false;
    return rval;
}


/*****************************************************************************
 * INTEL-SA-00075-Unprovisioning-Tool Messages
 *****************************************************************************/
void print_tool_banner(void) {
    printf("\nINTEL-SA-00075-Unprovisioning-Tool -- Release 0.8\n");
    printf("Copyright (C) 2003-2012, 2017 Intel Corporation.  All rights reserved\n\n");
}


/*****************************************************************************
 * INTEL-SA-00075-Unprovisioning-Tool 
 *****************************************************************************/

int main(int argc, char **argv) {
    print_tool_banner();
    if (argc>1 && !strncmp(argv[1],"-d",2)) {
        if (strlen(argv[2]) < MAX_DEV_NODE_PATH) {
            dev_path = calloc(MAX_DEV_NODE_PATH,1);
            memcpy(dev_path, argv[2], strlen(argv[2]));
            custom_dev_node = true;
        }
    }
    printf("\n-----------------------------------------------------------\n");
    int ret = check_amt_provision_status();
    if (ret < 0) {
        goto out;
    }
    if (ret == 0) {
        printf("System is in unprovisioned state. Exiting.\n");
        goto out;
    }

    ret = get_provisioning_control_mode();
    if (ret == 0) {
        printf("Control Mode: CLIENT / CCM\n");
    }
    if (ret == 2) {
        printf("Control Mode: ADMIN / ACM\n");
        printf("\tError: Cannot Unprovision - System provisioned in Admin Control"
                " Mode.\n");
        printf("\tUnprovision via Intel(R) MEBX. Press CTRL+P during system boot. "
            "Or Contact OEM\n");
        goto out;
    }
    if (ret == -1) {
        printf("Control Mode: Undetermined\n");
    } 

    ret = check_amt_unprovisioning_status();
    if (ret < 0) {
        goto out;
    }

    printf("Attempting Unprovisioning:\n");
    ret = un_provision_amt_ccm();
    if (ret < 0) {
        goto out;
    }

    ret = check_amt_unprovisioning_status();
    if (ret < 0) {
        goto out;
    }

    out: 
    printf("\n----------------------------------------------------------\n");
    return ret;
}
