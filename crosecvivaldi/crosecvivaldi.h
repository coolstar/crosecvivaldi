#ifndef __CROS_EC_REGS_H__
#define __CROS_EC_REGS_H__

#define BIT(nr) (1UL << (nr))

#include <pshpack1.h>

/*****************************************************************************/
/*
 *  "Get the Keyboard Config". An EC implementing this command is expected to be
 *  vivaldi capable, i.e. can send action codes for the top row keys.
 *  Additionally, capability to send function codes for the same keys is
 *  optional and acceptable.
 *
 *  Note: If the top row can generate both function and action codes by
 *  using a dedicated Fn key, it does not matter whether the key sends
 *  "function" or "action" codes by default. In both cases, the response
 *  for this command will look the same.
 */
#define EC_CMD_GET_KEYBD_CONFIG 0x012A

 /* Possible values for the top row keys */
enum action_key {
	TK_ABSENT = 0,
	TK_BACK = 1,
	TK_FORWARD = 2,
	TK_REFRESH = 3,
	TK_FULLSCREEN = 4,
	TK_OVERVIEW = 5,
	TK_BRIGHTNESS_DOWN = 6,
	TK_BRIGHTNESS_UP = 7,
	TK_VOL_MUTE = 8,
	TK_VOL_DOWN = 9,
	TK_VOL_UP = 10,
	TK_SNAPSHOT = 11,
	TK_PRIVACY_SCRN_TOGGLE = 12,
	TK_KBD_BKLIGHT_DOWN = 13,
	TK_KBD_BKLIGHT_UP = 14,
	TK_PLAY_PAUSE = 15,
	TK_NEXT_TRACK = 16,
	TK_PREV_TRACK = 17,
	TK_KBD_BKLIGHT_TOGGLE = 18,
	TK_MICMUTE = 19,
	TK_MENU = 20,
};

/*
 * Max & Min number of top row keys, excluding Esc and Screenlock keys.
 * If this needs to change, please create a new version of the command.
 */
#define MAX_TOP_ROW_KEYS 15
#define MIN_TOP_ROW_KEYS 10

 /*
  * Is the keyboard capable of sending function keys *in addition to*
  * action keys. This is possible for e.g. if the keyboard has a
  * dedicated Fn key.
  */
#define KEYBD_CAP_FUNCTION_KEYS		BIT(0)
  /*
   * Whether the keyboard has a dedicated numeric keyboard.
   */
#define KEYBD_CAP_NUMERIC_KEYPAD	BIT(1)
   /*
	* Whether the keyboard has a screenlock key.
	*/
#define KEYBD_CAP_SCRNLOCK_KEY		BIT(2)

struct ec_response_keybd_config {
	/*
	 *  Number of top row keys, excluding Esc and Screenlock.
	 *  If this is 0, all Vivaldi keyboard code is disabled.
	 *  (i.e. does not expose any tables to the kernel).
	 */
	UINT8 num_top_row_keys;

	/*
	 *  The action keys in the top row, in order from left to right.
	 *  The values are filled from enum action_key. Esc and Screenlock
	 *  keys are not considered part of top row keys.
	 */
	UINT8 action_keys[MAX_TOP_ROW_KEYS];

	/* Capability flags */
	UINT8 capabilities;

};

#include <poppack.h>

#endif /* __CROS_EC_REGS_H__ */