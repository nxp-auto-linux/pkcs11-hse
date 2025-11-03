// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

/*
 * Firmware version (major component) and type-id extraction
 *
 * Usage:
 *   --fw-version-major : prints the version-major
 *   --fw-type-id       : prints the HSE FW type id
 *
 * Enables firmware-version/type-based compilation, ensuring feature enablement
 * regardless of SoC platform.
 *
 * Extracts the major number from the HSE firmware header,
 * specifically from the HSE_FW_VERSION macro defined in hse_target.h.
 *
 * The extracted 'majorVersion' is printed so it can be captured
 * by the Makefile during build time and used as a macro definition
 */

#include <stdio.h>
#include <string.h>

#include "hse_target.h"
#include "hse_srv_attr.h"

int main(int argc, char *argv[]) {
    hseAttrFwVersion_t fw_version = HSE_FW_VERSION;
    if (argc != 2)
        return -1;
    if (!strcmp(argv[1], "--fw-version-major"))
        printf("%u\n", fw_version.majorVersion);
    else if (!strcmp(argv[1], "--fw-type-id"))
        printf("%u\n", fw_version.fwTypeId);
    else
        return -1;

    return 0;
}
