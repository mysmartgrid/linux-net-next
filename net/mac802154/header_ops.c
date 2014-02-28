/*
 * Copyright (C) 2014 Fraunhofer ITWM
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Written by:
 * Phoebe Buckheister <phoebe.buckheister@itwm.fraunhofer.de>
 */

#include <net/mac802154.h>
#include <net/ieee802154.h>

static void ieee802154_haddr_copy_swap(u8 *dest, const u8 *src)
{
	int i;
	for (i = 0; i < IEEE802154_ADDR_LEN; i++)
		dest[IEEE802154_ADDR_LEN - i - 1] = src[i];
}

static int
ieee802154_hdr_push_addr(u8 *buf, const struct ieee802154_addr *addr,
			 bool omit_pan)
{
	int pos = 0;

	if (addr->addr_type == IEEE802154_ADDR_NONE)
		return 0;

	if (!omit_pan) {
		buf[pos++] = addr->pan_id & 0xFF;
		buf[pos++] = addr->pan_id >> 8;
	}

	switch (addr->addr_type) {
	case IEEE802154_ADDR_SHORT:
		buf[pos++] = addr->short_addr & 0xFF;
		buf[pos++] = addr->short_addr >> 8;
		break;

	case IEEE802154_ADDR_LONG:
		ieee802154_haddr_copy_swap(buf + pos, addr->hwaddr);
		pos += IEEE802154_ADDR_LEN;
		break;

	default:
		return -EINVAL;
	}

	return pos;
}

static int
ieee802154_hdr_push_sechdr(u8 *buf, const struct ieee802154_sechdr *hdr)
{
	int pos = 0;

	buf[pos++] = hdr->sc;
	buf[pos++] = (hdr->frame_ctr >>  0) & 0xFF;
	buf[pos++] = (hdr->frame_ctr >>  8) & 0xFF;
	buf[pos++] = (hdr->frame_ctr >> 16) & 0xFF;
	buf[pos++] = (hdr->frame_ctr >> 24) & 0xFF;

	switch (IEEE802154_SCF_KEY_ID_MODE(hdr->sc)) {
	case IEEE802154_SCF_KEY_IMPLICIT:
		return pos;

	case IEEE802154_SCF_KEY_INDEX:
		break;

	case IEEE802154_SCF_KEY_SHORT_INDEX:
		buf[pos++] = hdr->key_source.pan.short_addr & 0xFF;
		buf[pos++] = hdr->key_source.pan.short_addr >> 8;
		buf[pos++] = hdr->key_source.pan.pan_id & 0xFF;
		buf[pos++] = hdr->key_source.pan.pan_id >> 8;
		break;

	case IEEE802154_SCF_KEY_HW_INDEX:
		ieee802154_haddr_copy_swap(buf + pos, hdr->key_source.hw);
		pos += IEEE802154_ADDR_LEN;
		break;
	}

	buf[pos++] = hdr->key_id;

	return pos;
}

int
ieee802154_hdr_push(struct sk_buff *skb, const struct ieee802154_hdr *hdr)
{
	u8 buf[MAC802154_FRAME_HARD_HEADER_LEN];
	int pos = 2;
	u16 fc = hdr->fc;
	int rc;

	buf[pos++] = hdr->seq;

	fc &= ~IEEE802154_FC_DAMODE_MASK;
	fc |= (hdr->dest.addr_type << IEEE802154_FC_DAMODE_SHIFT)
		& IEEE802154_FC_DAMODE_MASK;

	rc = ieee802154_hdr_push_addr(buf + pos, &hdr->dest, false);
	if (rc < 0)
		return -EINVAL;
	pos += rc;

	fc &= ~IEEE802154_FC_SAMODE_MASK | ~IEEE802154_FC_INTRA_PAN;
	fc |= (hdr->source.addr_type << IEEE802154_FC_SAMODE_SHIFT)
		& IEEE802154_FC_SAMODE_MASK;

	if (hdr->source.pan_id == hdr->dest.pan_id &&
	    hdr->dest.addr_type != IEEE802154_ADDR_NONE)
		fc |= IEEE802154_FC_INTRA_PAN;

	rc = ieee802154_hdr_push_addr(buf + pos, &hdr->source,
				      fc & IEEE802154_FC_INTRA_PAN);
	if (rc < 0)
		return -EINVAL;
	pos += rc;

	if (fc & IEEE802154_FC_SECEN) {
		IEEE802154_FC_SET_VERSION(fc, 1);

		rc = ieee802154_hdr_push_sechdr(buf + pos, &hdr->sec);
		if (rc < 0)
			return -EINVAL;

		pos += rc;
	}

	buf[0] = fc & 0xFF;
	buf[1] = fc >> 8;

	memcpy(skb_push(skb, pos), buf, pos);
	skb_reset_mac_header(skb);
	skb->mac_len = pos;

	return pos;
}

static u16 ieee802154_hdr_get_u16(const u8 *buf)
{
	return buf[0] | (buf[1] << 8);
}

static u32 ieee802154_hdr_get_u32(const u8 *buf)
{
	return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

static int
ieee802154_hdr_get_addr(const u8 *buf, int mode, bool omit_pan,
			struct ieee802154_addr *addr)
{
	int pos = 0;

	addr->addr_type = mode;

	if (mode == IEEE802154_ADDR_NONE)
		return 0;

	if (!omit_pan) {
		addr->pan_id = ieee802154_hdr_get_u16(buf + pos);
		pos += 2;
	}

	if (mode == IEEE802154_ADDR_SHORT) {
		addr->short_addr = ieee802154_hdr_get_u16(buf + pos);
		return pos + 2;
	} else {
		ieee802154_haddr_copy_swap(addr->hwaddr, buf + pos);
		return pos + IEEE802154_ADDR_LEN;
	}
}

static int ieee802154_hdr_addr_len(int mode, bool omit_pan)
{
	int pan_len = omit_pan ? 0 : 2;

	switch (mode) {
	case IEEE802154_ADDR_NONE: return 0;
	case IEEE802154_ADDR_SHORT: return 2 + pan_len;
	case IEEE802154_ADDR_LONG: return IEEE802154_ADDR_LEN + pan_len;
	default: return -EINVAL;
	}
}

static int
ieee802154_hdr_get_sechdr(const u8 *buf, struct ieee802154_sechdr *hdr)
{
	int pos = 0;
	u32 short_index;

	hdr->sc = buf[pos++];
	hdr->frame_ctr = ieee802154_hdr_get_u32(buf + pos);
	pos += 4;

	switch (IEEE802154_SCF_KEY_ID_MODE(hdr->sc)) {
	case IEEE802154_SCF_KEY_IMPLICIT:
		return pos;

	case IEEE802154_SCF_KEY_INDEX:
		break;

	case IEEE802154_SCF_KEY_SHORT_INDEX:
		short_index = ieee802154_hdr_get_u32(buf + pos);
		pos += 4;
		hdr->key_source.pan.pan_id = short_index >> 16;
		hdr->key_source.pan.short_addr = short_index & 0xFFFF;
		break;

	case IEEE802154_SCF_KEY_HW_INDEX:
		ieee802154_haddr_copy_swap(hdr->key_source.hw,
					   buf + pos);
		pos += IEEE802154_ADDR_LEN;
		break;
	}

	hdr->key_id = buf[pos++];

	return pos;
}

static int ieee802154_hdr_sechdr_len(u8 sc)
{
	switch (IEEE802154_SCF_KEY_ID_MODE(sc)) {
	case IEEE802154_SCF_KEY_IMPLICIT: return 5;
	case IEEE802154_SCF_KEY_INDEX: return 6;
	case IEEE802154_SCF_KEY_SHORT_INDEX: return 10;
	case IEEE802154_SCF_KEY_HW_INDEX: return 14;
	default: return -EINVAL;
	}
}

static int ieee802154_hdr_minlen(u16 fc)
{
	int dlen, slen;

	dlen = ieee802154_hdr_addr_len(IEEE802154_FC_DAMODE(fc), false);
	slen = ieee802154_hdr_addr_len(IEEE802154_FC_SAMODE(fc),
				       fc & IEEE802154_FC_INTRA_PAN);

	if (slen < 0 || dlen < 0)
		return -EINVAL;

	return 3 + dlen + slen + (fc & IEEE802154_FC_SECEN ? 1 : 0);
}

static int
ieee802154_hdr_get_addrs(const u8 *buf, struct ieee802154_hdr *hdr)
{
	int pos = 0;

	pos += ieee802154_hdr_get_addr(buf + pos,
				       IEEE802154_FC_DAMODE(hdr->fc),
				       false, &hdr->dest);
	pos += ieee802154_hdr_get_addr(buf + pos,
				       IEEE802154_FC_SAMODE(hdr->fc),
				       hdr->fc & IEEE802154_FC_INTRA_PAN,
				       &hdr->source);

	if (hdr->fc && IEEE802154_FC_INTRA_PAN)
		hdr->source.pan_id = hdr->dest.pan_id;

	return pos;
}

int
ieee802154_hdr_pull(struct sk_buff *skb, struct ieee802154_hdr *hdr)
{
	int pos = 3, rc;

	if (!pskb_may_pull(skb, 3))
		return -EINVAL;

	hdr->fc = ieee802154_hdr_get_u16(skb->data);
	hdr->seq = skb->data[2];

	rc = ieee802154_hdr_minlen(hdr->fc);
	if (rc < 0 || !pskb_may_pull(skb, rc))
		return -EINVAL;

	pos += ieee802154_hdr_get_addrs(skb->data + pos, hdr);

	if (hdr->fc & IEEE802154_FC_SECEN) {
		int want = pos + ieee802154_hdr_sechdr_len(hdr->sec.sc);

		if (!pskb_may_pull(skb, want))
			return -EINVAL;

		pos += ieee802154_hdr_get_sechdr(skb->data + pos, &hdr->sec);
	}

	skb_pull(skb, pos);
	return 0;
}

int
ieee802154_hdr_peek_addrs(const struct sk_buff *skb, struct ieee802154_hdr *hdr)
{
	const u8 *buf = skb_mac_header(skb);
	int pos = 3, rc;

	if (buf + 3 > skb->tail)
		return -EINVAL;

	hdr->fc = ieee802154_hdr_get_u16(buf);
	hdr->seq = buf[2];

	rc = ieee802154_hdr_minlen(hdr->fc);
	if (rc < 0 || buf + rc > skb->tail)
		return -EINVAL;

	ieee802154_hdr_get_addrs(skb->data + pos, hdr);
	return 0;
}
