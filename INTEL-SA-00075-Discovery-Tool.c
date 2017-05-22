/******************************************************************************
 * Intel-SA-00075-Discovery-Tool
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
    if (cl->fd != -1)
        close(cl->fd);
    cl->fd = -1;
    cl->buf_size = 0;
    cl->prot_ver = 0;
    cl->initialized = false;
}

#define MAX_DEV_NODE_PATH 12
char *dev_path;
bool custom_dev_node = false;
bool corporate_sku_check = false;
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
        if (!corporate_sku_check) {
            mei_err(me, "IOCTL_MEI_CONNECT_CLIENT receive message. err=%d\n",
                    result);
        }
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
    } else { /* rc < 0 */
        mei_err(me, "write failed on select with status %zd\n", rc);
        goto out;
    }

    rc = written;
    out: if (rc < 0)
        mei_deinit(me);

    return rc;
}

/***************************************************************************
 * Intel(R) AMT
 ***************************************************************************/

#define AMT_MAJOR_VERSION 1
#define AMT_MINOR_VERSION 1

#define AMT_STATUS_SUCCESS                0x0
#define AMT_STATUS_INTERNAL_ERROR         0x1
#define AMT_STATUS_NOT_READY              0x2
#define AMT_STATUS_INVALID_AMT_MODE       0x3
#define AMT_STATUS_INVALID_MESSAGE_LENGTH 0x4

#define AMT_STATUS_HOST_IF_EMPTY_RESPONSE  0x4000
#define AMT_STATUS_SDK_RESOURCES      0x1004

#define AMT_BIOS_VERSION_LEN   65
#define AMT_VERSIONS_NUMBER    50
#define AMT_UNICODE_STRING_LEN 20

struct amt_unicode_string {
    uint16_t length;
    char string[AMT_UNICODE_STRING_LEN];
}__attribute__((packed));

struct amt_version_type {
    struct amt_unicode_string description;
    struct amt_unicode_string version;
}__attribute__((packed));

struct amt_version {
    uint8_t major;
    uint8_t minor;
}__attribute__((packed));

struct amt_code_versions {
    uint8_t bios[AMT_BIOS_VERSION_LEN];
    uint32_t count;
    struct amt_version_type versions[AMT_VERSIONS_NUMBER];
}__attribute__((packed));

/***************************************************************************
 * Intel(R) AMT -  Host Interface
 ***************************************************************************/

struct amt_host_if_msg_header {
    struct amt_version version;
    uint16_t _reserved;
    uint32_t command;
    uint32_t length;
}__attribute__((packed));

struct amt_host_if_resp_header {
    struct amt_host_if_msg_header header;
    uint32_t status;
    unsigned char data[0];
}__attribute__((packed));

const uuid_le MEI_IAMTHIF = UUID_LE(0x12f80028, 0xb4b7, 0x4b2d, 0xac, 0xa8,
        0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c);

#define AMT_HOST_IF_CODE_VERSIONS_REQUEST  0x0400001A
#define AMT_HOST_IF_CODE_VERSIONS_RESPONSE 0x0480001A

const struct amt_host_if_msg_header CODE_VERSION_REQ = { .version = {
AMT_MAJOR_VERSION, AMT_MINOR_VERSION }, ._reserved = 0, .command =
AMT_HOST_IF_CODE_VERSIONS_REQUEST, .length = 0 };

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

static void amt_host_if_deinit(struct amt_host_if *acmd) {
    mei_deinit(&acmd->mei_cl);
    acmd->initialized = false;
}

static uint32_t amt_verify_code_versions(
        const struct amt_host_if_resp_header *resp) {
    uint32_t status = AMT_STATUS_SUCCESS;
    struct amt_code_versions *code_ver;
    size_t code_ver_len;
    uint32_t ver_type_cnt;
    uint32_t len;
    uint32_t i;

    code_ver = (struct amt_code_versions *) resp->data;
    /* length - sizeof(status) */
    code_ver_len = resp->header.length - sizeof(uint32_t);
    ver_type_cnt = code_ver_len - sizeof(code_ver->bios)
            - sizeof(code_ver->count);
    if (code_ver->count != ver_type_cnt / sizeof(struct amt_version_type)) {
        status = AMT_STATUS_INTERNAL_ERROR;
        goto out;
    }

    for (i = 0; i < code_ver->count; i++) {
        len = code_ver->versions[i].description.length;

        if (len > AMT_UNICODE_STRING_LEN) {
            status = AMT_STATUS_INTERNAL_ERROR;
            goto out;
        }

        len = code_ver->versions[i].version.length;
        if (code_ver->versions[i].version.string[len] != '\0'
                || len != strlen(code_ver->versions[i].version.string)) {
            status = AMT_STATUS_INTERNAL_ERROR;
            goto out;
        }
    }
    out: return status;
}

static uint32_t amt_verify_response_header(uint32_t command,
        const struct amt_host_if_msg_header *resp_hdr, uint32_t response_size) {
    if (response_size < sizeof(struct amt_host_if_resp_header)) {
        return AMT_STATUS_INTERNAL_ERROR;
    } else if (response_size
            != (resp_hdr->length + sizeof(struct amt_host_if_msg_header))) {
        return AMT_STATUS_INTERNAL_ERROR;
    } else if (resp_hdr->command != command) {
        return AMT_STATUS_INTERNAL_ERROR;
    } else if (resp_hdr->_reserved != 0) {
        return AMT_STATUS_INTERNAL_ERROR;
    } else if (resp_hdr->version.major != AMT_MAJOR_VERSION
            || resp_hdr->version.minor < AMT_MINOR_VERSION) {
        return AMT_STATUS_INTERNAL_ERROR;
    }
    return AMT_STATUS_SUCCESS;
}

static uint32_t amt_host_if_call(struct amt_host_if *acmd,
        const unsigned char *command, ssize_t command_sz, uint8_t **read_buf,
        uint32_t rcmd, unsigned int expected_sz) {
    uint32_t in_buf_sz;
    uint32_t out_buf_sz;
    ssize_t written;
    uint32_t status;
    struct amt_host_if_resp_header *msg_hdr;

    in_buf_sz = acmd->mei_cl.buf_size;
    *read_buf = (uint8_t *) malloc(sizeof(uint8_t) * in_buf_sz);
    if (*read_buf == NULL)
        return AMT_STATUS_SDK_RESOURCES;
    memset(*read_buf, 0, in_buf_sz);
    msg_hdr = (struct amt_host_if_resp_header *) *read_buf;

    written = mei_send_msg(&acmd->mei_cl, command, command_sz,
            acmd->send_timeout);
    if (written != command_sz)
        return AMT_STATUS_INTERNAL_ERROR;

    out_buf_sz = mei_recv_msg(&acmd->mei_cl, *read_buf, in_buf_sz, 2000);
    if (out_buf_sz <= 0)
        return AMT_STATUS_HOST_IF_EMPTY_RESPONSE;

    status = msg_hdr->status;
    if (status != AMT_STATUS_SUCCESS)
        return status;

    status = amt_verify_response_header(rcmd, &msg_hdr->header, out_buf_sz);
    if (status != AMT_STATUS_SUCCESS)
        return status;

    if (expected_sz && expected_sz != out_buf_sz)
        return AMT_STATUS_INTERNAL_ERROR;

    return AMT_STATUS_SUCCESS;
}

static uint32_t amt_get_code_versions(struct amt_host_if *cmd,
        struct amt_code_versions *versions) {
    struct amt_host_if_resp_header *response = NULL;
    uint32_t status;

    status = amt_host_if_call(cmd, (const unsigned char *) &CODE_VERSION_REQ,
            sizeof(CODE_VERSION_REQ), (uint8_t **) &response,
            AMT_HOST_IF_CODE_VERSIONS_RESPONSE, 0);

    if (status != AMT_STATUS_SUCCESS)
        goto out;

    status = amt_verify_code_versions(response);
    if (status != AMT_STATUS_SUCCESS)
        goto out;

    memcpy(versions, response->data, sizeof(struct amt_code_versions));
    out: 
    if (response != NULL)
        free(response);

    return status;
}

/*****************************************************************************
 * SKU Decode Context
 *****************************************************************************/

typedef union {
    struct {
        unsigned reserved :1;
        unsigned intel_quiet_system_technology :1;
        unsigned asf :1;
        unsigned intel_amt :1;
        unsigned intel_standard_manageability :1;
        unsigned reserved_1 :1;
        unsigned reserved_2 :1;
        unsigned reserved_3 :1;
        unsigned intel_remote_pc_assist :1;
        unsigned reserved_4 :4;
        unsigned intel_anti_theft_technology :1;
        unsigned corporate_sku :1;
        unsigned level_3_manageability_upgrade :1;
        unsigned intel_small_business_technology :1; 
        unsigned reserved_5 :15;
    };
    uint32_t full_sku_value;
} sku_decode;

void decode_amt_sku_information(sku_decode SKU) {
    printf("\n-----------------SKU Information-----------------\n");
    if (SKU.intel_small_business_technology) {
        printf("\t\t Intel(R) Small Business Technology\n");
    }
    if (SKU.level_3_manageability_upgrade) {
        printf("\t\t Level 3 Manageability Upgrade\n");
    }
    if (SKU.corporate_sku) {
        printf("\t\t Corporate SKU\n");
    }
    if (SKU.intel_anti_theft_technology) {
        printf("\t\t Intel(R) Anti-Theft Technology (Intel(R) AT)\n");
    }
    if (SKU.intel_remote_pc_assist) {
        printf("\t\t Intel(R) Remote PC Assist\n");
    }
    if (SKU.intel_standard_manageability) {
        printf("\t\t Intel(R) Standard Manageability\n");
    }
    if (SKU.intel_amt) {
        printf("\t\t Intel(R) Active Management Technology\n");
    }
    if (SKU.asf) {
        printf("\t\t ASF\n");
    }
    if (SKU.intel_quiet_system_technology) {
        printf("\t\t Intel(R) Quiet System Technology \n");
    }
    printf("-------------------------------------------------\n\n");
}

/*****************************************************************************
 * FW Decode Major.Minor.Hotfix.Build
 *****************************************************************************/

typedef struct {
    uint8_t me_major_num;
    uint8_t me_minor_num;
    uint8_t me_hotfix_num;
} fw_decode;

#define MAX_FW_STRING 20
void decode_me_fw_information(char *fw_string, fw_decode *FW) {
    fw_string[MAX_FW_STRING -1] = 0;
    char *num_string = strtok(fw_string, ".");
    if (num_string != NULL) {
        FW->me_major_num = strtoul(num_string, NULL, 0);
    }
    num_string = strtok(NULL, ".");
    if (num_string != NULL) {
        FW->me_minor_num = strtoul(num_string, NULL, 0);
    }
    num_string = strtok(NULL, ".");
    if (num_string != NULL) {
        FW->me_hotfix_num = strtoul(num_string, NULL, 0);
    }
}

/*****************************************************************************
 * Discover Vulnerability
 *****************************************************************************/

bool discover_vulnerability(sku_decode SKU, fw_decode FW, uint32_t me_build_num) {
    //sku
    if (SKU.corporate_sku || SKU.intel_small_business_technology
            || SKU.intel_standard_manageability || SKU.intel_amt) {

        //Major Version <6
        if (FW.me_major_num < 6) {
            return false;
        }
        //Major Version  6 and Minor == 0 
        if (FW.me_major_num == 6 && FW.me_minor_num == 0 
            && me_build_num >= 3000) {
            return false;
        }
        //Major Version  6 and Minor >= 1  and Build number >= 3000
        if (FW.me_major_num == 6 && FW.me_minor_num > 0
                && me_build_num >= 3000) {
            return false;
        }
        //Major Versions 7, 8 ,9, 10 and Build number >= 3000
        if (FW.me_major_num >= 7 && FW.me_major_num <= 10
                && me_build_num >= 3000) {
            return false;
        }
        //Major Version 11 and Minor <= 6 with Build Number >= 3000
        if (FW.me_major_num == 11 && FW.me_minor_num <= 6
                && me_build_num >= 3000) {
            return false;
        }
        //Major Version 11 and Minor >= 7 
        if (FW.me_major_num == 11 && FW.me_minor_num >= 7) {
            return false;
        }
        //Major Versions >=12
        if (FW.me_major_num >= 12) {
            return false;
        }
    } else {
        return false;
    }
    return true;
}

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

int get_provisioning_status(void) {
    struct amt_host_if acmd;
    int rval = 0;

    if (!amt_host_if_init(&acmd, 5000, false)) {
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
        printf("Error: Failed to retrieve response for provisioning status: %08X\n",
                response.Status);
        rval = -1;
        goto failed_check_amt_provision_status;
    } else {
        if (response.ProvisioningState == PROVISIONING_STATE_PRE) {
            printf("PROVISIONING_STATE = PRE\n"); //Not Provisioned
            rval = 0;
        }
        if (response.ProvisioningState == PROVISIONING_STATE_IN) {
            printf("PROVISIONING_STATE = IN\n");
            rval = 1;
        }
        if (response.ProvisioningState == PROVISIONING_STATE_POST) {
            printf("PROVISIONING_STATE = POST\n"); //Provisioned
            rval = 2;
        }
    }
    failed_check_amt_provision_status: mei_deinit(&acmd.mei_cl);
    return rval;
}

/*****************************************************************************
 * Check Corporate Sku with MKHI HECI connection
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

struct mkhi_host_if {
    struct mei mei_cl;
    unsigned long send_timeout;
    bool initialized;
};

const uuid_le MEI_MKHI_HIF = UUID_LE(0x8e6a6715, 0x9abc, 0x4043, 0x88, 0xef,
        0x9e, 0x39, 0xc6, 0xf6, 0x3e, 0x0f);

static bool mkhi_host_if_init(struct mkhi_host_if *acmd,
        unsigned long send_timeout, bool verbose) {
    acmd->send_timeout = (send_timeout) ? send_timeout : 20000;
    acmd->initialized = mei_init(&acmd->mei_cl, &MEI_MKHI_HIF, 0, verbose);
    return acmd->initialized;
}

const uuid_le MEI_MKHI_HIF_FIX = UUID_LE(0x55213584, 0x9a29, 0x4916, 0xba, 0xdf, 0xf, 
    0xb7, 0xed, 0x68, 0x2a, 0xeb);

static bool mkhi_host_if_fix_init(struct mkhi_host_if *acmd,
        unsigned long send_timeout, bool verbose) {
    acmd->send_timeout = (send_timeout) ? send_timeout : 20000;
    acmd->initialized = mei_init(&acmd->mei_cl, &MEI_MKHI_HIF_FIX, 0, verbose);
    return acmd->initialized;
}

static bool enable_fixed_clients_check(void)
{
    FILE *fp = fopen("/sys/kernel/debug/mei/allow_fixed_address", "w");
    if (!fp) {
        fp  = fopen("/sys/kernel/debug/mei0/allow_fixed_address", "w");
        if (!fp) {
            return false;                    
        }
    }
    int ret = (fwrite("Y", sizeof(char), 1, fp) == 1) ? 0 : -1;    
    fclose(fp);
    
    struct mkhi_host_if mkhi_cmd;
    bool heci_init_call = mkhi_host_if_fix_init(&mkhi_cmd, 5000, false);
    if (!ret) {
        if (!heci_init_call) {
            mei_deinit(&mkhi_cmd.mei_cl);
            return false;
        } else {
            mei_deinit(&mkhi_cmd.mei_cl);
            return true;
        }         
    } else {
        mei_deinit(&mkhi_cmd.mei_cl);
        return false;
    }
}

int check_if_corporate_sku_by_connection(void) {
    corporate_sku_check = true;
    int rval = 0;
    //Check AMT connection
    struct amt_host_if amt_cmd;
    bool heci_init_call = amt_host_if_init(&amt_cmd, 5000, false);
    if (!heci_init_call) {
        mei_deinit(&amt_cmd.mei_cl);
        rval = -2;
    }
    //Check HCI connection
    struct mkhi_host_if mkhi_cmd;
    heci_init_call = mkhi_host_if_init(&mkhi_cmd, 5000, false);
    if (rval < 0) {
        if (!heci_init_call) {
            mei_deinit(&mkhi_cmd.mei_cl);
            rval = -1;
        }        
    }
    //Enable fixed client and attempt hci heci connect
    if (rval == -1) {
        if (enable_fixed_clients_check()) {
            rval = -2;
        } else {
            printf("Error: Failed connection to Intel(R) MEI Subsystem. Contact OEM.\n");
        }
    }
    //De-Initialize if handles were created
    if (mkhi_cmd.initialized) {
        mei_deinit(&mkhi_cmd.mei_cl);
    }
    if (amt_cmd.initialized) {
        mei_deinit(&amt_cmd.mei_cl);
    }
    corporate_sku_check = false;
    return rval;
}

int parse_code_version_information(uint32_t status, sku_decode *SKU,
        uint32_t *me_build_num, struct amt_code_versions *ver, char *fw_string) {
    int rval = 0;
    switch (status) {
    case AMT_STATUS_HOST_IF_EMPTY_RESPONSE:
        printf("\nIntel(R) AMT: DISABLED\n");
        rval = -1;
        goto failed_parse_code_version_information;
        break;
    case AMT_STATUS_SUCCESS:
        printf("\n------------------Firmware Information--------------------\n");
        printf("\nIntel(R) AMT: ENABLED\n");
        uint32_t i;
        for (i = 0; i < ver->count; i++) {
            printf("%s:\t%s\n", ver->versions[i].description.string,
                    ver->versions[i].version.string);
            if (!strncmp(ver->versions[i].description.string, "Sku", 3)) {
                SKU->full_sku_value = strtoul(ver->versions[i].version.string,
                        NULL, 0);
                if (!SKU->full_sku_value) {
                    printf("Error: Unable to determine system state, contact OEM\n");
                    rval = -1;
                    goto failed_parse_code_version_information; //should be fatal
                }
            }
            if (!strncmp(ver->versions[i].description.string, "AMT", 3)) {
                if( strlen(ver->versions[i].version.string) < MAX_FW_STRING) {
                    strncpy(fw_string, ver->versions[i].version.string,
                        sizeof(strlen(ver->versions[i].version.string)));
                } else {
                    printf("Error: Unable to determine system state, contact OEM\n");
                    rval = -1;
                    goto failed_parse_code_version_information;
                }                 
            }
            if (!strncmp(ver->versions[i].description.string, "Build Number", 12)) {
                *me_build_num = strtoul(ver->versions[i].version.string, NULL, 0);
            }
        }
        break;
    default:
        printf("Error: Unable to determine system state, contact OEM\n");
        rval = -1;
        break;
    }
    failed_parse_code_version_information: 
    return rval;
}


/*****************************************************************************
 * Check Provisioning Control Mode
 *****************************************************************************/
typedef struct
{
    PTHI_MESSAGE_HEADER Header;
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
    return rval;
}


/*****************************************************************************
 * INTEL-SA-00075-Discovery-Tool Messages
 *****************************************************************************/
void print_vulnerability_message(bool provisioned, bool vulnerable) {
    printf("\n------------------Vulnerability Status--------------------\n");
    if (vulnerable) {
    if (provisioned) {
        printf( "Based on the version of the Intel(R) MEI, the System is Vulnerable.\n"
            "Run the unprovision tool to reset AMT to factory settings.\n"
            "If Vulnerable, contact your OEM for support and remediation of this system.\n"
            "For more information, refer to CVE-2017-5689 at:\n"
            "https://nvd.nist.gov/vuln/detail/CVE-2017-5689 or the Intel security advisory\n"
            "Intel-SA-00075 at:\n"
            "https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr");
    } else {
        printf( "Based on the version of the Intel(R) MEI, the System is Vulnerable.\n"
            "If Vulnerable, contact your OEM for support and remediation of this system.\n"
            "For more information, refer to CVE-2017-5689 at:\n"
            "https://nvd.nist.gov/vuln/detail/CVE-2017-5689 or the Intel security advisory\n"
            "Intel-SA-00075 at:\n"
            "https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr");
    }
    } else {
        printf("System is not Vulnerable, no further action needed.\n");
    }
    printf("\n----------------------------------------------------------\n\n");
}

void print_tool_banner(void) {
    printf("\nINTEL-SA-00075-Discovery-Tool -- Release 0.8\n");
    printf("Copyright (C) 2003-2012, 2017 Intel Corporation.  All rights reserved\n\n");
}


/*****************************************************************************
 * INTEL-SA-00075-Discovery-Tool 
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
    bool provisioned = false;
    int ret = check_if_corporate_sku_by_connection();
    if (ret == -1) {
        goto out;
    }
    if (ret == -2) {
        print_vulnerability_message(provisioned, false); //false, false
        goto out;
    }

    struct amt_host_if acmd;
    if (!amt_host_if_init(&acmd, 5000, false)) {
        ret = -1;
        goto out;
    }
    struct amt_code_versions ver;
    uint32_t status = amt_get_code_versions(&acmd, &ver);
    amt_host_if_deinit(&acmd);

    sku_decode SKU;
    char fw_string[MAX_FW_STRING];
    memset(fw_string, 0, MAX_FW_STRING);
    fw_decode FW;
    uint32_t me_build_num;
    ret = parse_code_version_information(status, &SKU, &me_build_num, &ver, fw_string);
    if (ret < 0) {
        goto out;
    }

    decode_amt_sku_information(SKU);

    decode_me_fw_information(fw_string, &FW);

    ret = get_provisioning_status();
    if (ret > 0) {
        provisioned = true;
    }

    if (provisioned) {
        ret = get_provisioning_control_mode();
        if (ret == 1) {
            printf("Control Mode: CLIENT / CCM\n");
        }
        if (ret == 2) {
            printf("Control Mode: ADMIN / ACM\n");
        }
        if (ret == -1 || ret == 0) {
            printf("Control Mode: Undetermined\n");
        }       
    }


    if (!discover_vulnerability(SKU, FW, me_build_num)) {
        print_vulnerability_message(provisioned, false);
    } else {
        print_vulnerability_message(provisioned, true);
    }

    out:
    if (custom_dev_node) {
    	free(dev_path);
    } 
    return ret;
}
