/*********************************************************************
 * PROFINET IO Device Emulation - GSDML Configuration
 *
 * Customized version of p-net sample app GSDML header for use as
 * a PROFINET mock/emulation device for integration testing.
 *
 * Based on p-net by rt-labs AB (GPLv3).
 ********************************************************************/

#ifndef APP_GSDML_H
#define APP_GSDML_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pnet_api.h>

#define APP_GSDML_API 0

/*
 * Device identity - emulates a generic PROFINET IO device.
 * The station name is set at runtime via command-line argument.
 */
#define APP_GSDML_DEFAULT_STATION_NAME "pnmock-device"

/* GSDML tag: VendorID
 * Using PROFINET test vendor ID range.
 * Real Siemens = 0x002A, Beckhoff = 0x0004, Phoenix = 0x0119
 * We use rt-labs default for compatibility with the sample GSDML file. */
#define APP_GSDML_VENDOR_ID 0x0493

/* GSDML tag: DeviceID */
#define APP_GSDML_DEVICE_ID 0x0002

/* Used in DCP communication - OEM identification */
#define APP_GSDML_OEM_VENDOR_ID 0xcafe
#define APP_GSDML_OEM_DEVICE_ID 0xee02

/* I&M0 data - Identification & Maintenance */
#define APP_GSDML_IM_HARDWARE_REVISION 1
#define APP_GSDML_IM_VERSION_MAJOR     1
#define APP_GSDML_IM_VERSION_MINOR     0

#define APP_GSDML_SW_REV_PREFIX       'V'
#define APP_GSDML_PROFILE_ID          0x1234
#define APP_GSDML_PROFILE_SPEC_TYPE   0x5678
#define APP_GSDML_IM_REVISION_COUNTER 0

#define APP_GSDML_EXAMPLE_SERIAL_NUMBER "PNMOCK-001"

/* I&M1 initial values */
#define APP_GSDML_TAG_FUNCTION "PN Mock Device"
#define APP_GSDML_TAG_LOCATION "Lab Network"
#define APP_GSDML_IM_DATE      "2024-01-01 00:00"
#define APP_GSDML_DESCRIPTOR   "PROFINET Mock Emulation"
#define APP_GSDML_SIGNATURE    ""

/* GSDML tag: Writeable_IM_Records */
#define APP_GSDML_IM_SUPPORTED                                                 \
   (PNET_SUPPORTED_IM1 | PNET_SUPPORTED_IM2 | PNET_SUPPORTED_IM3)

/* GSDML tag: OrderNumber */
#define APP_GSDML_ORDER_ID "PNMOCK-DEV-001"

/* GSDML tag: ModuleInfo / Name */
#define APP_GSDML_PRODUCT_NAME "PROFINET Mock IO Device"

/* GSDML tag: MinDeviceInterval - 1 ms (32 * 31.25us) */
#define APP_GSDML_MIN_DEVICE_INTERVAL 32

#define APP_GSDML_DIAG_CUSTOM_USI 0x1234

/* Logbook entry constants */
#define APP_GSDML_LOGBOOK_ERROR_CODE   0x20
#define APP_GSDML_LOGBOOK_ERROR_DECODE 0x82
#define APP_GSDML_LOGBOOK_ERROR_CODE_1 PNET_ERROR_CODE_1_FSPM
#define APP_GSDML_LOGBOOK_ERROR_CODE_2 0x00
#define APP_GSDML_LOGBOOK_ENTRY_DETAIL 0xFEE1DEAD

/* Parameter indices */
#define APP_GSDML_PARAMETER_1_IDX    123
#define APP_GSDML_PARAMETER_2_IDX    124
#define APP_GSDML_PARAMETER_ECHO_IDX 125

/* Parameter data length */
#define APP_GSDML_PARAMETER_LENGTH 4

/* Default MAU type: Copper 100 Mbit/s Full duplex */
#define APP_GSDML_DEFAULT_MAUTYPE 0x10

/*
 * Module and submodule types
 */

typedef struct app_gsdml_module
{
   uint32_t id;
   const char * name;
   uint32_t submodules[];
} app_gsdml_module_t;

typedef struct app_gsdml_submodule
{
   uint32_t id;
   const char * name;
   uint32_t api;
   pnet_submodule_dir_t data_dir;
   uint16_t insize;
   uint16_t outsize;
   uint16_t parameters[];
} app_gsdml_submodule_t;

typedef struct
{
   uint32_t index;
   const char * name;
   uint16_t length;
} app_gsdml_param_t;

/*
 * Module/Submodule IDs
 *
 * The emulated device has:
 *   Slot 0: DAP (Device Access Point) - always present
 *   Slot 1: 8-bit digital input module
 *   Slot 2: 8-bit digital output module
 *   Slot 3: 8-bit digital I/O module
 *   Slot 4: Echo module (8 bytes in/out)
 */
#define APP_GSDML_MOD_ID_8_0_DIGITAL_IN     0x00000030
#define APP_GSDML_MOD_ID_0_8_DIGITAL_OUT    0x00000031
#define APP_GSDML_MOD_ID_8_8_DIGITAL_IN_OUT 0x00000032
#define APP_GSDML_MOD_ID_ECHO               0x00000040

#define APP_GSDML_SUBMOD_ID_DIGITAL_IN      0x00000130
#define APP_GSDML_SUBMOD_ID_DIGITAL_OUT     0x00000131
#define APP_GSDML_SUBMOD_ID_DIGITAL_IN_OUT  0x00000132
#define APP_GSDML_SUBMOD_ID_ECHO            0x00000140

#define APP_GSDML_INPUT_DATA_DIGITAL_SIZE   1 /* bytes */
#define APP_GSDML_OUTPUT_DATA_DIGITAL_SIZE  1 /* bytes */
#define APP_GSDML_INPUT_DATA_ECHO_SIZE      8 /* bytes */
#define APP_GSDML_OUTPUT_DATA_ECHO_SIZE     APP_GSDML_INPUT_DATA_ECHO_SIZE
#define APP_GSDML_ALARM_PAYLOAD_SIZE        1 /* bytes */

/* API functions */
const app_gsdml_module_t * app_gsdml_get_module_cfg (uint32_t module_id);
const app_gsdml_submodule_t * app_gsdml_get_submodule_cfg (uint32_t submodule_id);
const app_gsdml_param_t * app_gsdml_get_parameter_cfg (
   uint32_t submodule_id,
   uint32_t index);

#ifdef __cplusplus
}
#endif

#endif /* APP_GSDML_H */
