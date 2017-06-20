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

#include "INTEL-SA-00075.h"

/*****************************************************************************
 * Check UnProvisioning State
 *****************************************************************************/
/*
 * Function:     Reveals if the previous un-provisioning attempt was successful.
 *               Returns 1-->Un-Provisioning succeeded, 
 *                       0-->Un-Provisioning failed, 
 *                      -1-->Failures.
 * Dependencies: None
 * Arguments:    Intel(R) MEI kernel device node path
 * Description:  (1) Prepares command structure to send an GetUnprovisioningState 
 *                   request message to the connected Intel(R) AMT client in 
 *                   Intel(R) ME FW.
 *               (2) Calls the send receive message/ command function and  it 
 *                   records the unprovisioning state in the response structure 
 *                   memmber State.
 *                   OR--> Sets return rval to -1 if connection fails and jumps
 *                   to exit label failed_check_amt_unprovisioning_status
 *               (3) In either cases above, code now reaches the exit label where
 *                   it returns rval. 
 * Notes:        None
 */
int check_amt_unprovisioning_status(const char *device_path) {
    CFG_GetUnprovisioningState_Request request = { 
        .Header.Version.MajorNumber = 1, 
        .Header.Version.MinorNumber = 1, 
        .Header.Command.Class = 4,
        .Header.Command.Operation = 0x68, 
        .Header.Length = sizeof(request.Header) 
    };
    CFG_GetUnprovisioningState_Response response;

    CLIENT_TYPE client_type = AMT_CLIENT_TYPE;

    int rval = heci_send_recieve_message((const unsigned char *) &request,
            sizeof(request), (unsigned char *) &response, sizeof(response),
            client_type, device_path);

    if (rval < 0 || response.Status != AMT_STATUS_SUCCESS) {
        printf("Error: Failed Unprovisioning. Use Intel(R) MEBX to unprovision."
                " Or Contact OEM\n");
        rval = -1;
        goto failed_check_amt_unprovisioning_status;
    } else {
        if (!response.State) {
            printf("System needs to be unprovisioned.\n");
        } else {
            printf("System is already unprovisioned.\n");
            rval = -1;
        }
    }

failed_check_amt_unprovisioning_status: 
    return rval;
}

/*****************************************************************************
 * CCM UNPROVISION COMMAND
 *****************************************************************************/
/*
 * Function:     Attempts Full Intel (R) AMT UN-Provisioning in client mode/ CCM.
 * Returns:      0-->successful
 *              -1-->failure cases.
 * Dependencies: System is Intel(R) AMT provisioned in client mode.
 * Arguments:    
 * Description:  (1) Prepares command structure to send an CFG_Unprovisioning_Request 
 *                   request message to the connected Intel(R) AMT client in 
 *                   Intel(R) ME FW.
 *               (2) Calls the send receive message/ command function and  it 
 *                   records the unprovisioning response in the response structure 
 *                   memmber Status.
 *                   if Status is not AMT_STATUS_SUCCESS,
 *                   Sets return rval to -1 if connection fails and jumps
 *                   to exit label failed_un_provision_amt_ccm
 *               (3) In either cases above, code now reaches the exit label where
 *                   it returns rval.  
 * Notes:        None
 */
int un_provision_amt_ccm(const char *device_path) {
    CFG_PROVISIONING_MODE mode = CFG_PROVISIONING_MODE_NONE;
    CFG_Unprovision_Request request = { 
        .Header.Version.MajorNumber = AMT_MAJOR_VERSION, 
        .Header.Version.MinorNumber = AMT_MINOR_VERSION,
        .Header.Command.Class = 4, 
        .Header.Command.Operation = 0x10, 
        .Mode = mode, 
        .Header.Length = sizeof(request.Header) 
    };
    CFG_Unprovision_Response response;

    CLIENT_TYPE client_type = AMT_CLIENT_TYPE;

    int rval = heci_send_recieve_message((const unsigned char *) &request,
            sizeof(request), (unsigned char *) &response, sizeof(response),
            client_type, device_path);

    if (rval < 0 || response.Status != AMT_STATUS_SUCCESS) {
        printf(
                "Error: Failed Unprovisioning. Use Intel(R) MEBX to unprovision. "
                        "Or Contact OEM.");
        rval = -1;
        goto failed_un_provision_amt_ccm;
    } else {
        printf("\tSuccessfully Unprovisioned.\n");
    }

failed_un_provision_amt_ccm: 
    return rval;
}

/*****************************************************************************
 * INTEL-SA-00075-Unprovisioning-Tool Messages
 *****************************************************************************/
/*
 * Function:     Display tool banner along with copyright information.
 * Dependencies: None
 * Arguments:    None
 * Description:  None
 * Notes:        Ensure to update the release number every release.
 */
void print_tool_banner(void) {
    printf("\nINTEL-SA-00075-Unprovisioning-Tool -- Release 1.0\n");
    printf("Copyright (C) 2003-2012, 2017 Intel Corporation.  All rights reserved\n\n");
}

/*****************************************************************************
 * INTEL-SA-00075-Unprovisioning-Tool 
 *****************************************************************************/
/*
 * Function:     To un-provision client mode (CCM) AMT provisioned platform.
 * Dependencies: Root privilege/ permissions.
 * Arguments:    [INPUT] -d is the only expected command line option for 
 *               user defined /dev/mei# node
 * Description:  (1) Displays the tool version and copyright info
 *               (2) Ensures the tool was run with root permissions
 *               (3) Defaults to open /dev/mei0 node unless specified by user option
 *               (4) Checks if system is in provisioned state, if not - exits.
 *               (5) Checks if provisioning mode is ACM, if yes - exits.
 *                   Note it will attempt unprovisioning if mode is CCM/Unknown.
 *               (6) Checks if an UN-provisioning attempt has been made already.
 *                   Does nothing? (??Reboot-Message??) --Need this step?
 *               (7) Attempt UN-provisioning and exit if it fails.
 *               (8) Checks if the above UN-provisioning attempt go through.
 * Notes:        If everything went fine, run Discovery tool to ensure system is 
 *               unprovisioned/ not vulnerable. Note unprovisioning is a mitigation.
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

    printf("\n-----------------------------------------------------------\n");
    int ret = get_provisioning_status(dev_path, true);
    if (ret < 0) {
        goto out;
    }
    if (ret == 0) {
        printf("System is in unprovisioned state. Exiting.\n");
        goto out;
    }

    ret = get_provisioning_control_mode(dev_path);
    if (ret == 0) {
        printf("Control Mode: CLIENT / CCM\n");
    }
    if (ret == 2) {
        printf("Control Mode: ADMIN / ACM\n");
        printf("\tError: Cannot Unprovision - System provisioned in Admin Control"
                        " Mode.\n");
        printf("\tUnprovision via Intel(R) MEBX. Press CTRL+P during system boot."
                        " Or Contact OEM.\n");
        goto out;
    }
    if (ret == -1) {
        printf("Control Mode: Undetermined\n");
    }

    ret = check_amt_unprovisioning_status(dev_path);
    if (ret < 0) {
        goto out;
    }

    printf("Attempting Unprovisioning:\n");
    ret = un_provision_amt_ccm(dev_path);
    if (ret < 0) {
        goto out;
    }

    ret = check_amt_unprovisioning_status(dev_path);
    if (ret < 0) {
        goto out;
    }

out: 
    printf("\n----------------------------------------------------------\n");
    return ret;
}
