/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_KEYBOARD_H
#define __LINUX_KEYBOARD_H

#include <uapi/linux/keyboard.h>

#define U(x) ((x) ^ 0xf000)

typedef struct {
	unsigned short val;
} kunicode_t;

#define KUNICODE_INIT(value) (kunicode_t){ (value) }

static inline kunicode_t make_kunicode(unsigned short value)
{
	return KUNICODE_INIT(U(value));
}

static inline unsigned short kunicode_raw(kunicode_t unicode)
{
	return unicode.val;
}

/*
 * For now, export means the same as raw value because the size is the same as
 * the previous size.
 */
static inline unsigned short kunicode_export(kunicode_t unicode)
{
	return kunicode_raw(unicode);
}

static inline unsigned short kunicode_kval(kunicode_t unicode)
{
	return KVAL(kunicode_raw(unicode));
}

static inline unsigned char kunicode_ktyp(kunicode_t kunicode)
{
	return KTYP(kunicode_raw(kunicode));
}

static inline bool kunicode_eq(kunicode_t left, kunicode_t right)
{
	return kunicode_raw(left) == kunicode_raw(right);
}

struct notifier_block;
extern kunicode_t *key_maps[MAX_NR_KEYMAPS];
extern kunicode_t plain_map[NR_KEYS];

struct keyboard_notifier_param {
	struct vc_data *vc;	/* VC on which the keyboard press was done */
	int down;		/* Pressure of the key? */
	int shift;		/* Current shift mask */
	int ledstate;		/* Current led state */
	unsigned int value;	/* keycode, unicode value or keysym */
};

extern int register_keyboard_notifier(struct notifier_block *nb);
extern int unregister_keyboard_notifier(struct notifier_block *nb);
#endif
