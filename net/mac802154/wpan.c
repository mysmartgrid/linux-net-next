/*
 * Copyright 2007-2012 Siemens AG
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
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Sergey Lapin <slapin@ossfans.org>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/if_arp.h>

#include <net/rtnetlink.h>
#include <linux/nl802154.h>
#include <net/af_ieee802154.h>
#include <net/mac802154.h>
#include <net/ieee802154_netdev.h>
#include <net/ieee802154.h>
#include <net/wpan-phy.h>

#include "mac802154.h"

static inline int mac802154_fetch_skb_u8(struct sk_buff *skb, u8 *val)
{
	if (unlikely(!pskb_may_pull(skb, 1)))
		return -EINVAL;

	*val = skb->data[0];
	skb_pull(skb, 1);

	return 0;
}

static inline int mac802154_fetch_skb_u16(struct sk_buff *skb, u16 *val)
{
	if (unlikely(!pskb_may_pull(skb, 2)))
		return -EINVAL;

	*val = skb->data[0] | (skb->data[1] << 8);
	skb_pull(skb, 2);

	return 0;
}

static inline int mac802154_fetch_skb_u32(struct sk_buff *skb, u32 *val)
{
	if (unlikely(!pskb_may_pull(skb, 4)))
		return -EINVAL;

	*val = skb->data[0] | (skb->data[1] << 8) | (skb->data[2] << 16)
		| (skb->data[3] << 24);
	skb_pull(skb, 4);

	return 0;
}

static inline void mac802154_haddr_copy_swap(u8 *dest, const u8 *src)
{
	int i;
	for (i = 0; i < IEEE802154_ADDR_LEN; i++)
		dest[IEEE802154_ADDR_LEN - i - 1] = src[i];
}

static int
mac802154_wpan_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct mac802154_sub_if_data *priv = netdev_priv(dev);
	struct sockaddr_ieee802154 *sa =
		(struct sockaddr_ieee802154 *)&ifr->ifr_addr;
	int err = -ENOIOCTLCMD;

	spin_lock_bh(&priv->mib_lock);

	switch (cmd) {
	case SIOCGIFADDR:
		if (priv->pan_id == IEEE802154_PANID_BROADCAST ||
		    priv->short_addr == IEEE802154_ADDR_BROADCAST) {
			err = -EADDRNOTAVAIL;
			break;
		}

		sa->family = AF_IEEE802154;
		sa->addr.addr_type = IEEE802154_ADDR_SHORT;
		sa->addr.pan_id = priv->pan_id;
		sa->addr.short_addr = priv->short_addr;

		err = 0;
		break;
	case SIOCSIFADDR:
		dev_warn(&dev->dev,
			 "Using DEBUGing ioctl SIOCSIFADDR isn't recommened!\n");
		if (sa->family != AF_IEEE802154 ||
		    sa->addr.addr_type != IEEE802154_ADDR_SHORT ||
		    sa->addr.pan_id == IEEE802154_PANID_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_UNDEF) {
			err = -EINVAL;
			break;
		}

		priv->pan_id = sa->addr.pan_id;
		priv->short_addr = sa->addr.short_addr;

		err = 0;
		break;
	}

	spin_unlock_bh(&priv->mib_lock);
	return err;
}

static int mac802154_wpan_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (netif_running(dev))
		return -EBUSY;

	/* FIXME: validate addr */
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	mac802154_dev_set_ieee_addr(dev);
	return 0;
}

static int mac802154_header_create(struct sk_buff *skb,
				   struct net_device *dev,
				   unsigned short type,
				   const void *_daddr,
				   const void *_saddr,
				   unsigned len)
{
	const struct ieee802154_addr *saddr = _saddr;
	const struct ieee802154_addr *daddr = _daddr;
	struct ieee802154_addr dev_addr;
	struct mac802154_sub_if_data *priv = netdev_priv(dev);
	int pos = 2;
	u8 head[MAC802154_FRAME_HARD_HEADER_LEN];
	u16 fc;

	if (!daddr)
		return -EINVAL;

	head[pos++] = mac_cb(skb)->seq; /* DSN/BSN */
	fc = mac_cb_type(skb);
	if (mac_cb_is_ackreq(skb))
		fc |= IEEE802154_FC_ACK_REQ;

	fc |= IEEE802154_FC_SECEN;
	fc &= ~IEEE802154_FC_VERSION_MASK;
	fc |= (1 << IEEE802154_FC_VERSION_SHIFT) & IEEE802154_FC_VERSION_MASK;

	if (!saddr) {
		spin_lock_bh(&priv->mib_lock);

		if (priv->short_addr == IEEE802154_ADDR_BROADCAST ||
		    priv->short_addr == IEEE802154_ADDR_UNDEF ||
		    priv->pan_id == IEEE802154_PANID_BROADCAST) {
			dev_addr.addr_type = IEEE802154_ADDR_LONG;
			memcpy(dev_addr.hwaddr, dev->dev_addr,
			       IEEE802154_ADDR_LEN);
		} else {
			dev_addr.addr_type = IEEE802154_ADDR_SHORT;
			dev_addr.short_addr = priv->short_addr;
		}

		dev_addr.pan_id = priv->pan_id;
		saddr = &dev_addr;

		spin_unlock_bh(&priv->mib_lock);
	}

	if (daddr->addr_type != IEEE802154_ADDR_NONE) {
		fc |= (daddr->addr_type << IEEE802154_FC_DAMODE_SHIFT);

		head[pos++] = daddr->pan_id & 0xff;
		head[pos++] = daddr->pan_id >> 8;

		if (daddr->addr_type == IEEE802154_ADDR_SHORT) {
			head[pos++] = daddr->short_addr & 0xff;
			head[pos++] = daddr->short_addr >> 8;
		} else {
			mac802154_haddr_copy_swap(head + pos, daddr->hwaddr);
			pos += IEEE802154_ADDR_LEN;
		}
	}

	if (saddr->addr_type != IEEE802154_ADDR_NONE) {
		fc |= (saddr->addr_type << IEEE802154_FC_SAMODE_SHIFT);

		if ((saddr->pan_id == daddr->pan_id) &&
		    (saddr->pan_id != IEEE802154_PANID_BROADCAST)) {
			/* PANID compression/intra PAN */
			fc |= IEEE802154_FC_INTRA_PAN;
		} else {
			head[pos++] = saddr->pan_id & 0xff;
			head[pos++] = saddr->pan_id >> 8;
		}

		if (saddr->addr_type == IEEE802154_ADDR_SHORT) {
			head[pos++] = saddr->short_addr & 0xff;
			head[pos++] = saddr->short_addr >> 8;
		} else {
			mac802154_haddr_copy_swap(head + pos, saddr->hwaddr);
			pos += IEEE802154_ADDR_LEN;
		}
	}

	head[0] = fc;
	head[1] = fc >> 8;

	priv->frame_counter++;

	head[pos++] = 0x0d;
	head[pos++] = (priv->frame_counter >>  0) & 0xFF;
	head[pos++] = (priv->frame_counter >>  8) & 0xFF;
	head[pos++] = (priv->frame_counter >> 16) & 0xFF;
	head[pos++] = (priv->frame_counter >> 24) & 0xFF;
	head[pos++] = 0;

	memcpy(skb_push(skb, pos), head, pos);
	skb_reset_mac_header(skb);
	skb->mac_len = pos;

	return pos;
}

static int
mac802154_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	const u8 *hdr = skb_mac_header(skb);
	const u8 *tail = skb_tail_pointer(skb);
	struct ieee802154_addr *addr = (struct ieee802154_addr *)haddr;
	u16 fc;
	int da_type;

	if (hdr + 3 > tail)
		goto malformed;

	fc = hdr[0] | (hdr[1] << 8);

	hdr += 3;

	da_type = IEEE802154_FC_DAMODE(fc);
	addr->addr_type = IEEE802154_FC_SAMODE(fc);

	switch (da_type) {
	case IEEE802154_ADDR_NONE:
		if (fc & IEEE802154_FC_INTRA_PAN)
			goto malformed;
		break;
	case IEEE802154_ADDR_LONG:
		if (fc & IEEE802154_FC_INTRA_PAN) {
			if (hdr + 2 > tail)
				goto malformed;
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + IEEE802154_ADDR_LEN > tail)
			goto malformed;

		hdr += IEEE802154_ADDR_LEN;
		break;
	case IEEE802154_ADDR_SHORT:
		if (fc & IEEE802154_FC_INTRA_PAN) {
			if (hdr + 2 > tail)
				goto malformed;
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + 2 > tail)
			goto malformed;

		hdr += 2;
		break;
	default:
		goto malformed;

	}

	switch (addr->addr_type) {
	case IEEE802154_ADDR_NONE:
		break;
	case IEEE802154_ADDR_LONG:
		if (!(fc & IEEE802154_FC_INTRA_PAN)) {
			if (hdr + 2 > tail)
				goto malformed;
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + IEEE802154_ADDR_LEN > tail)
			goto malformed;

		mac802154_haddr_copy_swap(addr->hwaddr, hdr);
		hdr += IEEE802154_ADDR_LEN;
		break;
	case IEEE802154_ADDR_SHORT:
		if (!(fc & IEEE802154_FC_INTRA_PAN)) {
			if (hdr + 2 > tail)
				goto malformed;
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + 2 > tail)
			goto malformed;

		addr->short_addr = hdr[0] | (hdr[1] << 8);
		hdr += 2;
		break;
	default:
		goto malformed;
	}

	return sizeof(struct ieee802154_addr);

malformed:
	pr_debug("malformed packet\n");
	return 0;
}

static netdev_tx_t
mac802154_wpan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mac802154_sub_if_data *priv;
	u8 chan, page;

	priv = netdev_priv(dev);

	spin_lock_bh(&priv->mib_lock);
	chan = priv->chan;
	page = priv->page;
	spin_unlock_bh(&priv->mib_lock);

	if (chan == MAC802154_CHAN_NONE ||
	    page >= WPAN_NUM_PAGES ||
	    chan >= WPAN_NUM_CHANNELS) {
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	skb->skb_iif = dev->ifindex;
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	return mac802154_tx(priv, skb, page, chan);
}

static struct header_ops mac802154_header_ops = {
	.create		= mac802154_header_create,
	.parse		= mac802154_header_parse,
};

static const struct net_device_ops mac802154_wpan_ops = {
	.ndo_open		= mac802154_slave_open,
	.ndo_stop		= mac802154_slave_close,
	.ndo_start_xmit		= mac802154_wpan_xmit,
	.ndo_do_ioctl		= mac802154_wpan_ioctl,
	.ndo_set_mac_address	= mac802154_wpan_mac_addr,
};

static void mac802154_wpan_free(struct net_device *dev)
{
	struct mac802154_sub_if_data *priv = netdev_priv(dev);

	if (priv->tfm)
		crypto_free_aead(priv->tfm);

	free_netdev(dev);
}

static void key_static(struct crypto_aead *tfm)
{
	char key[16] = { 0x00, 0x4f, 0x30, 0x92, 0xdf, 0x53, 0xd4, 0x70, 0x17,
		0x29, 0xde, 0x1d, 0x31, 0xbb, 0x55, 0x45 };
	int err;

	err = crypto_aead_setkey(tfm, key, sizeof(key));
	printk("setkey: %i\n", err);
	if (err)
		return;

	err = crypto_aead_setauthsize(tfm, 4);
	printk("authsize: %i\n", err);
	if (err)
		return;
}

void mac802154_wpan_setup(struct net_device *dev)
{
	struct mac802154_sub_if_data *priv;

	dev->addr_len		= IEEE802154_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_ADDR_LEN);

	dev->hard_header_len	= MAC802154_FRAME_HARD_HEADER_LEN;
	dev->header_ops		= &mac802154_header_ops;
	dev->needed_tailroom	= 2 + 16 + 16; /* FCS + padding + MIC */
	dev->mtu		= IEEE802154_MTU;
	dev->tx_queue_len	= 300;
	dev->type		= ARPHRD_IEEE802154;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;

	dev->destructor		= mac802154_wpan_free;
	dev->netdev_ops		= &mac802154_wpan_ops;
	dev->ml_priv		= &mac802154_mlme_wpan;

	priv = netdev_priv(dev);
	priv->type = IEEE802154_DEV_WPAN;

	priv->chan = MAC802154_CHAN_NONE;
	priv->page = 0;

	spin_lock_init(&priv->mib_lock);

	get_random_bytes(&priv->bsn, 1);
	get_random_bytes(&priv->dsn, 1);

	priv->pan_id = IEEE802154_PANID_BROADCAST;
	priv->short_addr = IEEE802154_ADDR_BROADCAST;

	priv->tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
	printk("aead: %p\n", priv->tfm);

	if (IS_ERR(priv->tfm)) {
		pr_warn("could not allocate aead for %s\n", dev->name);
		priv->tfm = NULL;
	} else {
		key_static(priv->tfm);
	}
}

static int mac802154_process_data(struct net_device *dev, struct sk_buff *skb)
{
	return netif_rx_ni(skb);
}

static int
mac802154_subif_frame(struct mac802154_sub_if_data *sdata, struct sk_buff *skb)
{
	pr_debug("getting packet via slave interface %s\n", sdata->dev->name);

	spin_lock_bh(&sdata->mib_lock);

	switch (mac_cb(skb)->da.addr_type) {
	case IEEE802154_ADDR_NONE:
		if (mac_cb(skb)->sa.addr_type != IEEE802154_ADDR_NONE)
			/* FIXME: check if we are PAN coordinator */
			skb->pkt_type = PACKET_OTHERHOST;
		else
			/* ACK comes with both addresses empty */
			skb->pkt_type = PACKET_HOST;
		break;
	case IEEE802154_ADDR_LONG:
		if (mac_cb(skb)->da.pan_id != sdata->pan_id &&
		    mac_cb(skb)->da.pan_id != IEEE802154_PANID_BROADCAST)
			skb->pkt_type = PACKET_OTHERHOST;
		else if (!memcmp(mac_cb(skb)->da.hwaddr, sdata->dev->dev_addr,
				 IEEE802154_ADDR_LEN))
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	case IEEE802154_ADDR_SHORT:
		if (mac_cb(skb)->da.pan_id != sdata->pan_id &&
		    mac_cb(skb)->da.pan_id != IEEE802154_PANID_BROADCAST)
			skb->pkt_type = PACKET_OTHERHOST;
		else if (mac_cb(skb)->da.short_addr == sdata->short_addr)
			skb->pkt_type = PACKET_HOST;
		else if (mac_cb(skb)->da.short_addr ==
					IEEE802154_ADDR_BROADCAST)
			skb->pkt_type = PACKET_BROADCAST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	default:
		break;
	}

	spin_unlock_bh(&sdata->mib_lock);

	skb->dev = sdata->dev;

	sdata->dev->stats.rx_packets++;
	sdata->dev->stats.rx_bytes += skb->len;

	switch (mac_cb_type(skb)) {
	case IEEE802154_FC_TYPE_DATA:
		return mac802154_process_data(sdata->dev, skb);
	default:
		pr_warn("ieee802154: bad frame received (type = %d)\n",
			mac_cb_type(skb));
		kfree_skb(skb);
		return NET_RX_DROP;
	}
}

static int mac802154_parse_frame_start(struct sk_buff *skb)
{
	u8 *head = skb->data;
	u16 fc;

	if (mac802154_fetch_skb_u16(skb, &fc) ||
	    mac802154_fetch_skb_u8(skb, &(mac_cb(skb)->seq)))
		goto err;

	pr_debug("fc: %04x dsn: %02x\n", fc, head[2]);

	mac_cb(skb)->flags = IEEE802154_FC_TYPE(fc);
	mac_cb(skb)->sa.addr_type = IEEE802154_FC_SAMODE(fc);
	mac_cb(skb)->da.addr_type = IEEE802154_FC_DAMODE(fc);

	if (fc & IEEE802154_FC_INTRA_PAN)
		mac_cb(skb)->flags |= MAC_CB_FLAG_INTRAPAN;
	if (fc & IEEE802154_FC_SECEN)
		mac_cb(skb)->flags |= MAC_CB_FLAG_SECEN;

	if (mac_cb(skb)->da.addr_type != IEEE802154_ADDR_NONE) {
		if (mac802154_fetch_skb_u16(skb, &(mac_cb(skb)->da.pan_id)))
			goto err;

		/* source PAN id compression */
		if (mac_cb_is_intrapan(skb))
			mac_cb(skb)->sa.pan_id = mac_cb(skb)->da.pan_id;

		pr_debug("dest PAN addr: %04x\n", mac_cb(skb)->da.pan_id);

		if (mac_cb(skb)->da.addr_type == IEEE802154_ADDR_SHORT) {
			u16 *da = &(mac_cb(skb)->da.short_addr);

			if (mac802154_fetch_skb_u16(skb, da))
				goto err;

			pr_debug("destination address is short: %04x\n",
				 mac_cb(skb)->da.short_addr);
		} else {
			if (!pskb_may_pull(skb, IEEE802154_ADDR_LEN))
				goto err;

			mac802154_haddr_copy_swap(mac_cb(skb)->da.hwaddr,
						  skb->data);
			skb_pull(skb, IEEE802154_ADDR_LEN);

			pr_debug("destination address is hardware\n");
		}
	}

	if (mac_cb(skb)->sa.addr_type != IEEE802154_ADDR_NONE) {
		/* non PAN-compression, fetch source address id */
		if (!(mac_cb_is_intrapan(skb))) {
			u16 *sa_pan = &(mac_cb(skb)->sa.pan_id);

			if (mac802154_fetch_skb_u16(skb, sa_pan))
				goto err;
		}

		pr_debug("source PAN addr: %04x\n", mac_cb(skb)->da.pan_id);

		if (mac_cb(skb)->sa.addr_type == IEEE802154_ADDR_SHORT) {
			u16 *sa = &(mac_cb(skb)->sa.short_addr);

			if (mac802154_fetch_skb_u16(skb, sa))
				goto err;

			pr_debug("source address is short: %04x\n",
				 mac_cb(skb)->sa.short_addr);
		} else {
			if (!pskb_may_pull(skb, IEEE802154_ADDR_LEN))
				goto err;

			mac802154_haddr_copy_swap(mac_cb(skb)->sa.hwaddr,
						  skb->data);
			skb_pull(skb, IEEE802154_ADDR_LEN);

			pr_debug("source address is hardware\n");
		}
	}

	if (mac_cb(skb)->flags & MAC_CB_FLAG_SECEN) {
		u8 scf;
		if (mac802154_fetch_skb_u8(skb, &scf))
			goto err;

		mac_cb(skb)->sec_level = IEEE802154_SCF_SECLEVEL(scf);
		mac_cb(skb)->key_id_mode = IEEE802154_SCF_KEY_ID_MODE(scf);

		if (mac802154_fetch_skb_u32(skb, &mac_cb(skb)->frame_counter))
			goto err;

		switch (mac_cb(skb)->key_id_mode) {
		case 0:
			break;
		case 1:
			if (!pskb_may_pull(skb, 1))
				goto err;
			skb_pull(skb, 1);
			break;
		case 2:
			if (!pskb_may_pull(skb, 4))
				goto err;
			skb_pull(skb, 4);
			break;
		case 3:
			if (!pskb_may_pull(skb, 9))
				goto err;
			skb_pull(skb, 9);
			break;
		}
	}

	return 0;
err:
	return -EINVAL;
}

static int mac802154_decrypt(struct sk_buff *skb, struct mac802154_sub_if_data *subif)
{
	struct crypto_aead *tfm = subif->tfm;
	struct aead_request *req;
	struct scatterlist src, dst[2];
	int rc;
	unsigned int data_len;
	unsigned char *data;
	u8 iv[16];

	req = kzalloc(sizeof(*req) + crypto_aead_reqsize(tfm), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	iv[0] = 1; /* L = 2 -> L' = iv[0] = 1 */
	iv[1] = 0x02;
	iv[2] = 0x50;
	iv[3] = 0xc4;
	iv[4] = 0xff;
	iv[5] = 0xfe;
	iv[6] = 0x04;
	iv[7] = 0x81;
	iv[8] = 0x0c;
	iv[9] =  (mac_cb(skb)->frame_counter >> 24) & 0xFF;
	iv[10] = (mac_cb(skb)->frame_counter >> 16) & 0xFF;
	iv[11] = (mac_cb(skb)->frame_counter >>  8) & 0xFF;
	iv[12] = (mac_cb(skb)->frame_counter >>  0) & 0xFF;
	iv[13] = 0x05;

	printk("epacket");
	for (rc = 0; rc < skb->len; rc++) {
		printk(" %02x", *(skb->data + rc));
	}
	printk("\n");

	data = skb->data;
	data_len = skb->len - 4;

	sg_init_one(&src, data, data_len);
	sg_init_table(dst, 2);
	sg_set_buf(&dst[0], data, data_len);
	sg_set_buf(&dst[1], data + data_len, crypto_aead_authsize(tfm));

	aead_request_set_tfm(req, tfm);
	aead_request_set_crypt(req, &src, dst, data_len, iv);

	rc = crypto_aead_encrypt(req);
	if (rc)
		goto out;

	skb_trim(skb, skb->len - 4);

	printk("dpacket");
	for (rc = 0; rc < skb->len; rc++) {
		printk(" %02x", *(skb->data + rc));
	}
	printk("\n");
	rc = 0;

	pr_warn("decrypt done: %i\n", rc);

out:
	kfree(req);

	return rc;
}

void mac802154_wpans_rx(struct mac802154_priv *priv, struct sk_buff *skb)
{
	int ret;
	struct sk_buff *sskb;
	struct mac802154_sub_if_data *sdata;

	ret = mac802154_parse_frame_start(skb);
	if (ret) {
		pr_debug("got invalid frame\n");
		return;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &priv->slaves, list) {
		if (sdata->type != IEEE802154_DEV_WPAN)
			continue;

		sskb = skb_clone(skb, GFP_ATOMIC);
		if (!sskb)
			continue;

		if (mac802154_decrypt(sskb, sdata))
			continue;

		mac802154_subif_frame(sdata, sskb);
	}
	rcu_read_unlock();
}
