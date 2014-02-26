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

static int
ieee802154_hdr_pull_u8(struct sk_buff *skb, u8 *val)
{
	if (unlikely(!pskb_may_pull(skb, 1)))
		return -EINVAL;

	*val = skb->data[0];
	pskb_pull(skb, 1);

	return 0;
}

static int
ieee802154_hdr_pull_u16(struct sk_buff *skb, u16 *val)
{
	__le16 field;

	if (unlikely(!pskb_may_pull(skb, 2)))
		return -EINVAL;

	memcpy(&field, skb->data, 2);
	*val = le16_to_cpu(field);
	pskb_pull(skb, 2);

	return 0;
}

static int
ieee802154_hdr_pull_u32(struct sk_buff *skb, u32 *val)
{
	__le32 field;

	if (unlikely(!pskb_may_pull(skb, 4)))
		return -EINVAL;

	memcpy(&field, skb->data, 4);
	*val = le32_to_cpu(field);
	pskb_pull(skb, 4);

	return 0;
}

static int
ieee802154_hdr_pull_addr(struct sk_buff *skb, int mode, bool omit_pan,
			 struct ieee802154_addr *addr)
{
	addr->addr_type = mode;

	if (mode == IEEE802154_ADDR_NONE)
		return 0;

	if (!omit_pan && ieee802154_hdr_pull_u16(skb, &addr->pan_id))
		return -EINVAL;

	switch (mode) {
	case IEEE802154_ADDR_SHORT:
		if (ieee802154_hdr_pull_u16(skb, &addr->short_addr))
			return -EINVAL;
		break;

	case IEEE802154_ADDR_LONG:
		if (unlikely(!pskb_may_pull(skb, IEEE802154_ADDR_LEN)))
			return -EINVAL;

		ieee802154_haddr_copy_swap(addr->hwaddr, skb->data);
		pskb_pull(skb, IEEE802154_ADDR_LEN);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int
ieee802154_hdr_pull_sechdr(struct sk_buff *skb, struct ieee802154_sechdr *hdr)
{
	if (ieee802154_hdr_pull_u8(skb, &hdr->sc))
		return -EINVAL;

	if (ieee802154_hdr_pull_u32(skb, &hdr->frame_ctr))
		return -EINVAL;

	if (IEEE802154_SCF_KEY_ID_MODE(hdr->sc)) {
		u32 short_index;

		switch (IEEE802154_SCF_KEY_ID_MODE(hdr->sc)) {
		case IEEE802154_SCF_KEY_INDEX:
			break;

		case IEEE802154_SCF_KEY_SHORT_INDEX:
			if (ieee802154_hdr_pull_u32(skb, &short_index))
				return -EINVAL;

			hdr->key_source.pan.pan_id = short_index >> 16;
			hdr->key_source.pan.short_addr = short_index & 0xFFFF;
			break;

		case IEEE802154_SCF_KEY_HW_INDEX:
			if (unlikely(!pskb_may_pull(skb, IEEE802154_ADDR_LEN)))
				return -EINVAL;

			ieee802154_haddr_copy_swap(hdr->key_source.hw,
						   skb->data);
			pskb_pull(skb, IEEE802154_ADDR_LEN);
			break;
		}

		if (ieee802154_hdr_pull_u8(skb, &hdr->key_id))
			return -EINVAL;
	}

	return 0;
}

int
ieee802154_hdr_pull(struct sk_buff *skb, struct ieee802154_hdr *hdr)
{
	if (ieee802154_hdr_pull_u16(skb, &hdr->fc))
		return -EINVAL;

	if (ieee802154_hdr_pull_u8(skb, &hdr->seq))
		return -EINVAL;

	if (ieee802154_hdr_pull_addr(skb, IEEE802154_FC_DAMODE(hdr->fc),
				     false, &hdr->dest))
		return -EINVAL;

	if (ieee802154_hdr_pull_addr(skb, IEEE802154_FC_SAMODE(hdr->fc),
				     hdr->fc & IEEE802154_FC_INTRA_PAN,
				     &hdr->source))
		return -EINVAL;

	if (hdr->fc & IEEE802154_FC_INTRA_PAN)
		hdr->source.pan_id = hdr->dest.pan_id;

	if ((hdr->fc & IEEE802154_FC_SECEN) &&
	    ieee802154_hdr_pull_sechdr(skb, &hdr->sec))
		return -EINVAL;

	return 0;
}
