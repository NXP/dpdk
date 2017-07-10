#include <inttypes.h>
/**
 *  Macros to define Object Identifier
 */

enum dpaa2_debug_object_identifier {
	DPAA2_DEBUG_DPNI_STATS = 0,
	DPAA2_DEBUG_DPNI_ATTRIBUTES,
	DPAA2_DEBUG_DPNI_LINK_STATE,
	DPAA2_DEBUG_DPNI_MAX_FRAME_LENGTH,
	DPAA2_DEBUG_DPNI_MTU,
	DPAA2_DEBUG_DPNI_L3_CHKSUM_VALIDATION,
	DPAA2_DEBUG_DPNI_L4_CHKSUM_VALIDATION,
	DPAA2_DEBUG_DPNI_PRIMARY_MAC_ADDR,
	DPAA2_DEBUG_QBMAN_FQ_ATTR_CGRID,
	DPAA2_DEBUG_QBMAN_FQ_ATTR_DESTWQ,
	DPAA2_DEBUG_QBMAN_FQ_ATTR_TDTHRESH,
	DPAA2_DEBUG_QBMAN_FQ_ATTR_CTX,
	DPAA2_DEBUG_QBMAN_FQ_STATE_SCHEDSTATE,
	DPAA2_DEBUG_QBMAN_FQ_STATE_FRAME_COUNT,
	DPAA2_DEBUG_QBMAN_FQ_STATE_BYTE_COUNT,
	DPAA2_DEBUG_QBMAN_BP_INFO_HAS_FREE_BUFS,
	DPAA2_DEBUG_QBMAN_BP_INFO_IS_DEPLETED,
	DPAA2_DEBUG_QBMAN_BP_INFO_NUM_FREE_BUFS,
	DPAA2_DEBUG_DPSECI_ATTRIBUTES,
	DPAA2_DEBUG_DPSECI_COUNTERS,
	DPAA2_DEBUG_PER_SA_STATS,
	/*TODO: More objects need to be added as per requirement*/
};

/**
 *  Macros to define command on given object
 */

enum dpaa2_debug_command {
	DPAA2_DEBUG_CMD_GET = 0,
	DPAA2_DEBUG_CMD_RESET,
	DPAA2_DEBUG_CMD_SET
	/*TODO: More commands need to be added for other object operations*/
};

/**
 * Structure to define message format accepted by debug control thread
 *
 * @params
 * obj_id	Object identifier given by user. Use 'DPAA2_DEBUG_<X>' values.
 * cmd		Command like get/set/reset,given by user. Use 'DPAA2_DEBUG_<X>' values.
 * buffer_len	Length of buffer
 * buffer	Device name given by user.
 *
 */
typedef struct ipc_msg {
	uint16_t obj_id;
	uint8_t cmd;
	uint8_t buffer_len;
	char buffer[64];
} ipc_msg_t;

int dpaa2_platform_debug_init(void);
