/******************************************************************************
 * Intel-SA-00075.c
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

/*****************************************************************************
 * Intel(R) MEI
 *****************************************************************************/

/*
 * Close the device handle to the Intel(R) MEI driver
 * And reset the initialized flag.
 */
void mei_deinit(struct mei *cl) {
    if (cl->fd != -1)
        close(cl->fd);
    cl->fd = -1;
    cl->buf_size = 0;
    cl->prot_ver = 0;
    cl->initialized = false;
}

/*
 * Attempts to open the dev node for Intel(R) MEI device driver and establish
 * connection with specified client uuid.
 * Returns a boolean: True if the handle was established and connection was made
 * successfully, False otherwise.
 */
bool mei_init(struct mei *me, const uuid_le *guid, const char *device_path) {
    int result;
    struct mei_client *cl;
    struct mei_connect_client_data data = { 0 };

    me->fd = open(device_path, O_RDWR);
    if (me->fd == -1) {
        mei_err(me, "%s %s\nCannot establish a handle to the Intel(R) MEI driver." 
            " Refer to Tool User Guide for more information.\n", strerror(errno), 
            device_path);
        exit(-1);
    }
    memcpy(&me->guid, guid, sizeof(*guid));
    me->initialized = true;

    memcpy(&data.in_client_uuid, &me->guid, sizeof(me->guid));
    result = ioctl(me->fd, IOCTL_MEI_CONNECT_CLIENT, &data);
    if (result) {
        mei_err(me, "IOCTL_MEI_CONNECT_CLIENT receive message. err=%d\n", result);
        goto err;
    }
    cl = &data.out_client_properties;

    me->buf_size = cl->max_msg_length;
    me->prot_ver = cl->protocol_version;

    return true;
err: 
    mei_deinit(me);
    return false;
}

/*
 * Writes out the command/ message to the initialized Intel(R) MEI client connection
 * with specified length of the message/ command.
 * If write goes through, returns number of bytes written otherwise the errno value.
 * After the message is sent it de-initializes the connection. 
 */
ssize_t mei_send_msg(struct mei *me, const unsigned char *buffer, ssize_t len) {
    ssize_t written;
    ssize_t rc;

    written = write(me->fd, buffer, len);
    if (written < 0) {
        rc = -errno;
        mei_err(me, "write failed with status %zd %s\n", written, strerror(errno));
        goto out;
    } else {
        rc = written;
    }
out: 
    if (rc < 0) {
        mei_deinit(me);
    }
    return rc;
}

/*
 * Retrieves response of specified length in the response buffer within a timeout
 * value specified, Any failures here would cause the code to exit since the Intel(R)
 * MEI clients are irresponsive. Otherwise return value is 0 for successful reads.
 */
ssize_t mei_recv_msg(struct mei *me, unsigned char *buffer, ssize_t len) {
    //receive message
    ssize_t rc = read(me->fd, buffer, len);

    if (rc < 0) {
        mei_err(me, "read operation failed with status %zd %s\n", rc, 
            strerror(errno));
        mei_deinit(me);
    }
    return rc;
}

/*****************************************************************************
 * HECI send/ receive message
 *****************************************************************************/
/*
 * Function:     Send a message to a specific HECI client and retrieve responses
 *               after establishing heci connection with the specified client.
 * Returns:      0 -->Successful sending message and receiving responses. 
 *              -1 -->Failures
 * Dependencies: Command structure is properly initialized
 * Arguments:    # Request/ Message - void* to accept different message structures.
 *               # Size of the request.
 *               # Response - void* to commonly record all types of responses.
 *               # Size of the response.
 *               # Intel(R) MEI HECI client to connect to send/ recevie message/responses
 *               # Intel(R) MEI kernel device node path
 * Description:  (1) Establishes connection with Intel (R) AMT client in Intel(R) MEI
 *                   firmware. If connection fails, Sets return rval to -1 and jumps
 *                   to exit label failed_check_amt_provisioning_status. 
 *               (2) Calls the send message/ command function and records the 
 *                   number of bytes written which should equal  size of request, 
 *                   if not it sets rval to -1 and jumps to exit label.
 *               (3) It records the number of bytes received in out_buf_sz variable. 
 *                   If out_buf_sz <= 0  it sets the rval to -1 and jumps to exit tag.
 *                   Otherwise it records the response structure. 
 *               (4) In either cases above, code now reaches the exit label, where
 *                   it disconnects the Intel(R) AMT client connection, closes the 
 *                   open dev/mei# node and returns rval. 
 * Notes:        None
 */
int heci_send_recieve_message(const unsigned char *request, ssize_t req_len,
        unsigned char *response, ssize_t rsp_len, CLIENT_TYPE client_type,
        const char *device_path) {
    //Send receive message to a heci client
    int rval = 0;
    struct heci_host_if acmd;
    if (!heci_host_if_init(&acmd, 5000, device_path, client_type)) {
        rval = -1;
        goto failed_heci_send_recieve_message;
    }

    uint32_t written = mei_send_msg(&acmd.mei_cl, request, req_len);
    if (written != req_len) {
        rval = -1;
        goto failed_heci_send_recieve_message;
    }

    uint32_t out_buf_sz = mei_recv_msg(&acmd.mei_cl, response, rsp_len);
    if (out_buf_sz <= 0) {
        rval = -1;
        goto failed_heci_send_recieve_message;
    }
failed_heci_send_recieve_message: 
    mei_deinit(&acmd.mei_cl);
    return rval;
}

/***************************************************************************
 * Intel(R) AMT -  Host Interface
 ***************************************************************************/
/*
 * Passes the information required to connect to specific Intel(R) MEI clients.
 * The function is commonly called by the tools prior to sending commands to the
 * specified clients and also sets up the timeout values.
 */
bool heci_host_if_init(struct heci_host_if *acmd, unsigned long send_timeout,
        const char *device_path, CLIENT_TYPE client_type) {
    acmd->send_timeout = (send_timeout) ? send_timeout : 20000;
    switch (client_type) {
    //Connect appropriate client
    case AMT_CLIENT_TYPE:
        acmd->initialized = mei_init(&acmd->mei_cl, &MEI_IAMTHIF, device_path);
        break;
    case MKHI_CLIENT_TYPE:
        acmd->initialized = mei_init(&acmd->mei_cl, &MEI_MKHI_HIF, device_path);
        break;
    case MKHI_FIX_CLIENT_TYPE:
        acmd->initialized = mei_init(&acmd->mei_cl, &MEI_MKHI_HIF_FIX,
                device_path);
        break;
    default:
        printf("DEBUG %d\n", client_type);
        acmd->initialized = false;
        break;
    }
    return acmd->initialized;
}

/*****************************************************************************
 * Check Provisioning Control Mode
 *****************************************************************************/
/*
 * Function:     Retrieves the mode in which the Intel(R) AMT was provisioned.
 *               Returns 1-->CCM, 
 *                       2-->ACM, 
 *                       0-->Undetermined, 
 *                      -1-->Failures.
 * Dependencies: None
 * Arguments:    Intel(R) MEI kernel device node path
 * Description:  (1) Prepares command structure to send an GetControlMode request
 *                   message to the connected Intel(R) AMT client in Intel(R) ME FW.
 *               (2) Calls the send receive message/ command function 
 *                   and records the provisioning control mode in the 
 *                   response structure member ControlMode.
 *               (3) In either cases above, code now reaches the exit label, where
 *                   it returns rval. 
 * Notes:        None
 */
int get_provisioning_control_mode(const char *device_path) {
    CFG_GetControlMode_Request request = { 
        .Header.Version.MajorNumber = 1,
        .Header.Version.MinorNumber = 1, 
        .Header.Command.Class = 0x4,
        .Header.Command.Operation = 0x6B, 
        .Header.Length = sizeof(request.Header) 
    };
    CFG_GetControlMode_Response response;

    CLIENT_TYPE client_type = AMT_CLIENT_TYPE;
    int rval = heci_send_recieve_message((const unsigned char *) &request,
            sizeof(request), (unsigned char *) &response, sizeof(response),
            client_type, device_path);

    if (rval < 0 || response.Status != AMT_STATUS_SUCCESS) {
        rval = -1;
        goto failed_get_provisioning_control_mode;
    } else {
        rval = response.ControlMode;
    }

failed_get_provisioning_control_mode: 
    return rval;
}

/*****************************************************************************
 * Check Provisioned State
 *****************************************************************************/
/*
 * Function:     Reveals if the previous un-provisioning attempt was successful.
 *               Returns 0-->PROVISIONING_STATE_PRE 
 *                       1-->PROVISIONING_STATE_IN 
 *                       2-->PROVISIONING_STATE_POST
 *                      -1-->Failures
 * Dependencies: None
 * Arguments:    # Intel(R) MEI kernel device node path
 *               # Flag to track tool message handling for the discovery and unprovisioning
 * Description:  (1) Prepares command structure to send an GetProvisioningState request
 *                   message to the connected Intel(R) AMT client in Intel(R) ME FW.
 *               (2) Calls the send receive message/ command function 
 *                   and records the provisioning status in the  response structure 
 *                   member ProvisioningState.
 *               (3) In either cases above, code now reaches the exit label, where
 *                   it returns rval.
 * Notes:        None
 */
int get_provisioning_status(const char *device_path, bool unprovision) {
    CFG_GetProvisioningState_Request request = {
        .Header.Version.MajorNumber = 1, 
        .Header.Version.MinorNumber = 1,
        .Header.Command.Class = 4, 
        .Header.Command.Operation = 0x11,
        .Header.Length = sizeof(request.Header) 
    };
    CFG_GetProvisioningState_Response response;

    CLIENT_TYPE client_type = AMT_CLIENT_TYPE;
    int rval = heci_send_recieve_message((const unsigned char *) &request,
            sizeof(request), (unsigned char *) &response, sizeof(response),
            client_type, device_path);

    if (rval < 0 || response.Status != AMT_STATUS_SUCCESS) {
        rval = -1;
        if (unprovision) {
            printf("Error: Failed Unprovisioning. Use Intel(R) MEBX to "
                "unprovision. Or Contact OEM\n");
        } else {
            printf("Error: Failed to retrieve response for provisioning status:"
                    " %08X\n", response.Status);
        }
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
failed_check_amt_provision_status: 
    return rval;
}
