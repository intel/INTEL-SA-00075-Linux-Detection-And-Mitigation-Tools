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

#include "INTEL-SA-00075.h"

/***************************************************************************
 * Intel(R) AMT
 ***************************************************************************/
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

#define AMT_HOST_IF_CODE_VERSIONS_REQUEST  0x0400001A
#define AMT_HOST_IF_CODE_VERSIONS_RESPONSE 0x0480001A

const struct amt_host_if_msg_header CODE_VERSION_REQ = { 
    .version = {
        AMT_MAJOR_VERSION,
        AMT_MINOR_VERSION 
    }, 
    ._reserved = 0, 
    .command = AMT_HOST_IF_CODE_VERSIONS_REQUEST, 
    .length = 0 
};

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

static uint32_t amt_host_if_call(struct heci_host_if *acmd,
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

    written = mei_send_msg(&acmd->mei_cl, command, command_sz);
    if (written != command_sz)
        return AMT_STATUS_INTERNAL_ERROR;

    out_buf_sz = mei_recv_msg(&acmd->mei_cl, *read_buf, in_buf_sz);
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

static uint32_t amt_get_code_versions(struct heci_host_if *cmd,
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
    out: if (response != NULL)
        free(response);

    return status;
}

/*****************************************************************************
 * SKU Decode Context
 *****************************************************************************/
/* 
 * Since the code is expected to be run exclusively on Intel Silicon,
 * only little endian implementation of the bitfield is done.
 */
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

/*
 * SKU information is parsed per the bitfield definition in sku_decode
 * This information is used to print SKU features and also used in determining
 * Vulnerable skus per Intel-SA-00075
 */
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
        printf("\t\t Intel(R) Remote PC Assist Technology (Intel(R) RPAT)\n");
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

/*
 * Parses firmware version string sent by the Intel(R) MEI AMT client
 */
#define MAX_FW_STRING 20
void decode_me_fw_information(char *fw_string, fw_decode *FW) {
    if (fw_string != NULL) fw_string[MAX_FW_STRING - 1] = 0;
    char *token_start = fw_string;
    char *token_end = fw_string;
    if (token_start != NULL) {
        strsep(&token_end, ".");
        FW->me_major_num = strtoul(token_start, NULL, 0);
        token_start = token_end;
    }
    if (token_start != NULL) {
        strsep(&token_end, ".");
        FW->me_minor_num = strtoul(token_start, NULL, 0);
        token_start = token_end;
    }
    if (token_start != NULL) {
        strsep(&token_end, ".");
        FW->me_hotfix_num = strtoul(token_start, NULL, 0);
        token_start = token_end;
    }
}

/*****************************************************************************
 * Discover Vulnerability
 *****************************************************************************/
/*
 * Function to determine vulnerable sku ranges based on 
 * FW Version: Major#.Minor#.Hotfix# and Build#
 */
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
        //Major Version 11 and Minor = 7 and Build number: >= 1000 && < 2000  
        if (FW.me_major_num == 11 && FW.me_minor_num == 7
                && me_build_num >= 1000 && me_build_num < 2000) {
            return true;
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
 * Check Corporate Sku with MKHI HECI connection
 *****************************************************************************/
/*
 * Enables alternative MKHI/ HCI client connection within Intel(R) ME FW
 * Required to determine Intel(R) MEI firmware readiness.
 */
static bool enable_fixed_clients_check(const char *device_path) {
    FILE *fp = fopen("/sys/kernel/debug/mei/allow_fixed_address", "w");
    if (!fp) {
        fp = fopen("/sys/kernel/debug/mei0/allow_fixed_address", "w");
        if (!fp) {
            return false;
        }
    }
    int ret = (fwrite("Y", sizeof(char), 1, fp) == 1) ? 0 : -1;
    fclose(fp);

    struct heci_host_if mkhi_cmd;
    CLIENT_TYPE client_type = MKHI_FIX_CLIENT_TYPE;
    bool heci_init_call = heci_host_if_init(&mkhi_cmd, 5000, device_path,
            client_type);
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

/*
 * Function:     Checks if Intel(R) ME FW has an HCI/ MKHI client in the FW SKU.
 * Returns :     True --> Connection with the client was successful.
 *               False--> Connection with the client failed. 
 * Arguments:    # Intel(R) MEI kernel device node path
 * Dependencies: None.
 * Description:  None
 * Notes:       On Intel(R) ME FW version 6.0 connection of MKHI may fail and can 
 *              be achieved by enabling a allow_fixed address flag and an alternative UUID.
 */
static bool check_mei_init(struct mei *me, const uuid_le *guid,
        const char *device_path) {
    int result;
    bool rval = false;
    struct mei_connect_client_data data = { 0 };

    me->fd = open(device_path, O_RDWR);
    if (me->fd == -1) {
        mei_err(me, "%s %s\nCannot establish a handle to the Intel(R) MEI driver."
         " Refer to Tool User Guide for more information.\n",strerror(errno), 
         device_path);
        exit(-1);
    }
    memcpy(&me->guid, guid, sizeof(*guid));
    me->initialized = true;

    memcpy(&data.in_client_uuid, &me->guid, sizeof(me->guid));
    result = ioctl(me->fd, IOCTL_MEI_CONNECT_CLIENT, &data);
    if (result) {
        rval = false;
        goto err;
    }

    rval = true;
err: 
    mei_deinit(me);
    return rval;
}

/*
 * Function:     Checks if Intel(R) ME FW has an Intel(R) AMT client in the FW SKU.
 * Returns :     0--> Connection with Intel(R) AMT client was successful.
 *              -1--> Neither Intel(R) AMT nor MKHI clients were responsive. 
 *              -2--> Intel(R) AMT client was not responsive.
 * Arguments:    # Intel(R) MEI kernel device node path
 * Dependencies: None
 * Description:  If connection fails, then it tries to make connection with HCI/ MKHI 
 *               client to ensure Intel(R) MEI is responsive to avoid falsely 
 *               reporting absence of Intel(R) AMT client.
 * Notes:        On Intel(R) ME FW version 6.0 connection of MKHI may fail and can 
 *               be achieved by enabling a allow_fixed address flag and an alternative UUID.
 */
int check_if_corporate_sku_by_connection(const char *device_path) {
    int rval = 0;
    //Check AMT connection
    struct mei amt_mei_check;

    bool heci_init_call = check_mei_init(&amt_mei_check, &MEI_IAMTHIF,
            device_path);
    if (!heci_init_call) {
        rval = -2;
    } else {
        return rval;
    }
    //Check HCI connection
    CLIENT_TYPE client_type = MKHI_CLIENT_TYPE;
    struct heci_host_if mkhi_cmd;
    heci_init_call = heci_host_if_init(&mkhi_cmd, 5000, device_path,
            client_type);
    if (mkhi_cmd.initialized) {
        mei_deinit(&mkhi_cmd.mei_cl);
    }
    if (!heci_init_call) {
        rval = -1;
    } else {
        return rval;
    }

    if (enable_fixed_clients_check(device_path)) {
        //Unable to connect with Intel(R) MEI AMT client on MEI v6.0
        rval = -2;
    } else {
        printf("Error: Failed connection to Intel(R) MEI Subsystem."
            " Contact OEM.\n");
    }
    return rval;
}

/*
 * Parse, print and extract firmware information from the sku information retrieved
 * using the GetCodeVersion command going to the Intel(R) AMT client.
 */
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
        printf(
                "\n------------------Firmware Information--------------------\n");
        printf("\nIntel(R) AMT: ENABLED\n");
        uint32_t i;
        for (i = 0; i < ver->count; i++) {
            printf("%s:\t%s\n", ver->versions[i].description.string,
                    ver->versions[i].version.string);
            if (!strncmp(ver->versions[i].description.string, "Sku", 3)) {
                SKU->full_sku_value = strtoul(ver->versions[i].version.string,
                        NULL, 0);
                if (!SKU->full_sku_value) {
                    printf("Error: Unable to determine system state,"
                        " contact OEM\n");
                    rval = -1;
                    goto failed_parse_code_version_information;
                    //should be fatal
                }
            }
            if (!strncmp(ver->versions[i].description.string, "AMT", 3)) {
                if (strlen(ver->versions[i].version.string) < MAX_FW_STRING) {
                    strncpy(fw_string, ver->versions[i].version.string,
                            sizeof(strlen(ver->versions[i].version.string)));
                } else {
                    printf("Error: Unable to determine system state,"
                        " contact OEM\n");
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
 * INTEL-SA-00075-Discovery-Tool Messages
 *****************************************************************************/
void print_vulnerability_message(bool provisioned, bool vulnerable) {
    printf("\n------------------Vulnerability Status--------------------\n");
    if (vulnerable) {
        if (provisioned) {
            printf("Based on the version of the Intel(R) MEI, the System is Vulnerable.\n"
                   "Run the unprovision tool to reset AMT to factory settings.\n"
                   "If Vulnerable, contact your OEM for support and remediation of this system.\n"
                   "For more information, refer to CVE-2017-5689 at:\n"
                   "https://nvd.nist.gov/vuln/detail/CVE-2017-5689 or the Intel security advisory\n"
                   "Intel-SA-00075 at:\n"
                   "https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr");
        } else {
            printf("Based on the version of the Intel(R) MEI, the System is Vulnerable.\n"
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
    printf("\nINTEL-SA-00075-Discovery-Tool -- Release 1.0\n");
    printf("Copyright (C) 2003-2012, 2017 Intel Corporation. All rights reserved\n\n");
}

/*****************************************************************************
 * INTEL-SA-00075-Discovery-Tool 
 *****************************************************************************/
/*
 * Function:     Determine whether the Intel(R) MEI firmware version currently on
 *               the platform is vulnerable as per INTEL-SA-00075 advisory.
 * Dependencies: Root privilege/ permissions.
 * Arguments:    [INPUT] -d is the only expected command line option for 
 *               user defined /dev/mei# node
 * Description:  (1) Displays the tool version and copyright info
 *               (2) Ensures the tool was run with root permissions
 *               (3) Defaults to open /dev/mei0 node unless specified by user option
 *               (4) Checks the Intel (R) MEI fw sku to determine if it is a consumer
 *                   or a corporate sku by trying to connect to the Intel(R) AMT 
 *                   client in the Intel(R) ME fw and parsing GetCodeVersion output.
 *                   If it is determined to be a consumer sku it 
 *                   calls function to print system not vulnerable message and exits.
 *                   Another possibility is that application was not able to make 
 *                   any connection with the Intel(R) ME fw at all, in which case
 *                   it also exits after printing this failure instead to the screen.
 *               (5) If an Intel(R) AMT connection was successful, it then retrieves 
 *                   the firmware sku information by issuing the GetCodeVersion
 *                   command.
 *               (6) It then closes/ deinitializes the Intel(R) AMT connection
 *                   with the Intel(R) ME fw.
 *               (7) Information retrieved from Intel(R) AMT client in step 5 is 
 *                   parsed to record "firmware-version" (in a string fw_string), 
 *                   "SKU value" and build_number required in decision making of 
 *                   vulnerable skus.
 *                   Any failures reflected in return value of this function causes
 *                   the program to exit at this point.
 *               (8) The SKU value is parsed to record and print the SKU type.
 *               (9) The firmware string is parsed to record firmware: Major#, Minor#
 *                   and Hotfix# which is used in determining the vulnerable skus.
 *              (10) The system is checked to see if it is in a provisioned state
 *                   by calling a function that returns a positive value if provisioned.
 *                   If get_provisioning_status fails, it still continues to see if
 *                   sku is infact vulnerable.
 *              (11) If provisioned a function is called to determine provisioning mode.
 *              (12) At this point we have all the information to determine if the 
 *                   system is vulnerable along with its provisioning state and mode
 *                   and so a function is called to iterate
 *                   the SKU, FW: Major.Minor.Hotfix, build# to determine the
 *                   vulnerable skus. This function returns a boolean value to inform
 *                   a vulnerable sku.
 *              (13) The information in step 11 and 12 is used to print the vulnerability
 *                   status along side information on the provisioning status.
 *                   if system is vulnerable and provisioned additional message 
 *                   to perform the un-provisioning mitigation is provided.
 * Notes:        None.
 */
int main(int argc, char **argv) {
    print_tool_banner();

    if (geteuid() != 0) {
        mei_err(me, "Please run the tool with root privilege.\n");
        exit(-1);
    }

    const char *dev_path;
    if (argc > 1 && !strncmp(argv[1], "-d", 2)) {
        dev_path = argv[2];
    } else {
        dev_path = DEFAULT_MEI_DEV_NODE;
    }

    int ret = check_if_corporate_sku_by_connection(dev_path);
    if (ret == -1) {
        goto out;
    }
    if (ret == -2) {
        //not-provisioned, not-vulnerable
        print_vulnerability_message(false, false);
        goto out;
    }

    struct heci_host_if acmd;
    CLIENT_TYPE client_type = AMT_CLIENT_TYPE;
    if (!heci_host_if_init(&acmd, 5000, dev_path, client_type)) {
        ret = -1;
        goto out;
    }
    struct amt_code_versions ver;
    uint32_t status = amt_get_code_versions(&acmd, &ver);
    mei_deinit(&acmd.mei_cl);

    sku_decode SKU;
    char fw_string[MAX_FW_STRING];
    memset(fw_string, 0, MAX_FW_STRING);
    fw_decode FW;
    uint32_t me_build_num;
    ret = parse_code_version_information(status, &SKU, &me_build_num, &ver,
            fw_string);
    if (ret < 0) {
        goto out;
    }

    decode_amt_sku_information(SKU);

    decode_me_fw_information(fw_string, &FW);

    bool provisioned = false;
    ret = get_provisioning_status(dev_path, false);
    if (ret > 0) {
        provisioned = true;
    }

    if (provisioned) {
        ret = get_provisioning_control_mode(dev_path);
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
    return ret;
}
