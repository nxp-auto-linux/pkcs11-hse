// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

/*
 * Firmware version (major component) extraction
 *
 * Enables firmware-version-based compilation, ensuring feature enablement
 * regardless of SoC platform.
 *
 * Extracts the major number from the HSE firmware header,
 * specifically from the HSE_FW_VERSION macro defined in hse_target.h.
 *
 * The extracted 'majorVersion' is printed so it can be captured
 * by the Makefile during build time and used as a macro definition
 */

#include <stdio.h>

#include "hse_target.h"
#include "hse_srv_attr.h"

int main(void) {
    hseAttrFwVersion_t fw_version = HSE_FW_VERSION;

    printf("%u\n", fw_version.majorVersion);

    return 0;
}
