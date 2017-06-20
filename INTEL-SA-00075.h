/******************************************************************************
 * Intel-SA-00075.h
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

#define DEFAULT_MEI_DEV_NODE "/dev/mei0"

#define MEI_IAMTHIF UUID_LE(0x12f80028, 0xb4b7, 0x4b2d, 0xac, 0xa8, 0x46, 0xe0, \
 0xff, 0x65, 0x81, 0x4c)
#define MEI_MKHI_HIF  UUID_LE(0x8e6a6715, 0x9abc, 0x4043, 0x88, 0xef, 0x9e, 0x39,\
 0xc6, 0xf6, 0x3e, 0x0f)
#define MEI_MKHI_HIF_FIX UUID_LE(0x55213584, 0x9a29, 0x4916, 0xba, 0xdf, 0xf, \
0xb7, 0xed, 0x68, 0x2a, 0xeb)

/*****************************************************************************
 * Intel(R) MEI
 *****************************************************************************/
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

/***************************************************************************
 * Intel(R) AMT
 ***************************************************************************/

#define AMT_MAJOR_VERSION 1
#define AMT_MINOR_VERSION 1

#define AMT_STATUS_SUCCESS                  0x0
#define AMT_STATUS_INTERNAL_ERROR           0x1
#define AMT_STATUS_NOT_READY                0x2
#define AMT_STATUS_INVALID_AMT_MODE         0x3
#define AMT_STATUS_INVALID_MESSAGE_LENGTH   0x4

#define AMT_STATUS_HOST_IF_EMPTY_RESPONSE   0x4000
#define AMT_STATUS_SDK_RESOURCES            0x1004

typedef enum {
    AMT_CLIENT_TYPE = 1, MKHI_CLIENT_TYPE = 2, MKHI_FIX_CLIENT_TYPE = 3,
} CLIENT_TYPE;

struct heci_host_if {
    struct mei mei_cl;
    unsigned long send_timeout;
    bool initialized;
};

/*****************************************************************************
 * Check Provisioned State
 *****************************************************************************/
#define PROVISIONING_STATE_PRE 0
#define PROVISIONING_STATE_IN 1
#define PROVISIONING_STATE_POST 2

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

typedef struct {
    PTHI_MESSAGE_HEADER Header;
} CFG_GetProvisioningState_Request;

typedef struct {
    PTHI_MESSAGE_HEADER Header;
    uint32_t Status;
    uint32_t ProvisioningState;
} CFG_GetProvisioningState_Response;

/*****************************************************************************
 * MKHI Command constructs
 *****************************************************************************/
typedef struct {
    uint32_t GroupId :8;
    uint32_t Command :7;
    uint32_t IsResponse :1;
    uint32_t Reserved :8;
    uint32_t Result :8;
} MKHI_MESSAGE_HEADER;

typedef struct {
    MKHI_MESSAGE_HEADER Header;
} GEN_GET_VPRO_ALLOWED_Request;

typedef struct {
    MKHI_MESSAGE_HEADER Header;
    uint8_t VproAllowed;
} GEN_GET_VPRO_ALLOWED_Response;

/*****************************************************************************
 * Check Provisioning Control Mode
 *****************************************************************************/
typedef struct {
    PTHI_MESSAGE_HEADER Header;
} CFG_GetControlMode_Request;

typedef struct {
    PTHI_MESSAGE_HEADER Header;
    uint32_t Status;
    uint32_t ControlMode;  // returned upon success only
} CFG_GetControlMode_Response;

/*****************************************************************************
 * CCM UNPROVISION COMMAND
 *****************************************************************************/
typedef uint32_t AMT_STATUS;

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

/*****************************************************************************
 * Check UnProvisioning State
 *****************************************************************************/
typedef enum {
    CFG_UNPROVISIONING_STATE_NONE = 0, CFG_UNPROVISIONING_STATE_IN = 1,
} CFG_UNPROVISIONING_STATE;

typedef struct {
    PTHI_MESSAGE_HEADER Header;
} CFG_GetUnprovisioningState_Request;

typedef struct {
    PTHI_MESSAGE_HEADER Header;
    AMT_STATUS Status;
    CFG_UNPROVISIONING_STATE State;  // returned upon success only
} CFG_GetUnprovisioningState_Response;

/*****************************************************************************
 * Common Functions
 *****************************************************************************/

bool mei_init(struct mei *me, const uuid_le *guid, const char *device_path);

void mei_deinit(struct mei *cl);

ssize_t mei_recv_msg(struct mei *me, unsigned char *buffer, ssize_t len);

ssize_t mei_send_msg(struct mei *me, const unsigned char *buffer, ssize_t len);

int heci_send_recieve_message(const unsigned char *request, ssize_t req_len,
        unsigned char *response, ssize_t rsp_len, CLIENT_TYPE client_type,
        const char *device_path);

bool heci_host_if_init(struct heci_host_if *acmd, unsigned long send_timeout,
        const char *device_path, CLIENT_TYPE client_type);

int get_provisioning_control_mode(const char *device_path);

int get_provisioning_status(const char *device_path, bool unprovision);
