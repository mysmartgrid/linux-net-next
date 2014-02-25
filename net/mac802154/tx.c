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
#include <linux/if_arp.h>
#include <linux/crc-ccitt.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include <net/ieee802154_netdev.h>
#include <net/mac802154.h>
#include <net/wpan-phy.h>

#include "mac802154.h"

/* IEEE 802.15.4 transceivers can sleep during the xmit session, so process
 * packets through the workqueue.
 */
struct xmit_work {
	struct sk_buff *skb;
	struct work_struct work;
	struct mac802154_priv *priv;
	struct mac802154_sub_if_data *subif;
	u8 chan;
	u8 page;
	u8 iv[16];
	u8 auth_tag[16];
};

static int mac802154_encrypt(struct xmit_work *xw)
{
	struct crypto_aead *tfm = xw->subif->tfm;
	struct sk_buff *skb = xw->skb;
	struct aead_request *req;
	struct scatterlist src, dst[2];
	int rc;
	unsigned int data_len;
	unsigned char *data;

	req = kzalloc(sizeof(*req) + crypto_aead_reqsize(tfm), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	xw->iv[0] = 1; /* L = 2 -> L' = iv[0] = 1 */
	xw->iv[1] = 0xde;
	xw->iv[2] = 0xad;
	xw->iv[3] = 0xbe;
	xw->iv[4] = 0xef;
	xw->iv[5] = 0xca;
	xw->iv[6] = 0xfe;
	xw->iv[7] = 0xba;
	xw->iv[8] = 0xbe;
	xw->iv[9] =  (xw->subif->frame_counter >> 24) & 0xFF;
	xw->iv[10] = (xw->subif->frame_counter >> 16) & 0xFF;
	xw->iv[11] = (xw->subif->frame_counter >>  8) & 0xFF;
	xw->iv[12] = (xw->subif->frame_counter >>  0) & 0xFF;
	xw->iv[13] = 0x05;

//	printk("dpacket");
//	for (rc = 0; rc < skb->len - skb->mac_len; rc++) {
//		printk(" %02x", *(skb_mac_header(skb) + skb->mac_len + rc));
//	}
//	printk("\n");

	data = skb_mac_header(skb) + skb->mac_len;
	data_len = skb->len - skb->mac_len;

	sg_init_one(&src, data, data_len);
	sg_init_table(dst, 2);
	sg_set_buf(&dst[0], data, data_len);
	sg_set_buf(&dst[1], skb_put(skb, crypto_aead_authsize(tfm)),
			crypto_aead_authsize(tfm));
//	sg_set_buf(&dst[1], xw->auth_tag, crypto_aead_authsize(tfm));

	aead_request_set_tfm(req, tfm);
	aead_request_set_crypt(req, &src, dst, data_len, xw->iv);

	rc = crypto_aead_encrypt(req);
	if (rc)
		goto out;

//	printk("epacket");
//	for (rc = 0; rc < skb->len - skb->mac_len; rc++) {
//		printk(" %02x", *(skb_mac_header(skb) + skb->mac_len + rc));
//	}
//	printk("\n");
//	rc = 0;
//
//	pr_warn("encrypt done: %i\n", rc);

out:
	kfree(req);

	return rc;
}

static void mac802154_finalize(struct xmit_work *xw)
{
	struct sk_buff *skb = xw->skb;

	if (!(xw->priv->hw.flags & IEEE802154_HW_OMIT_CKSUM)) {
		u16 crc = crc_ccitt(0, skb->data, skb->len);
		u8 *data = skb_put(skb, 2);
		data[0] = crc & 0xff;
		data[1] = crc >> 8;
	}
}

static void mac802154_xmit_worker(struct work_struct *work)
{
	struct xmit_work *xw = container_of(work, struct xmit_work, work);
	struct mac802154_sub_if_data *sdata;
	int res;

	if (xw->subif->tfm) {
		res = mac802154_encrypt(xw);
		if (res) {
			pr_warn("encrypt failed: %i\n", res);
			goto early_out;
		}
	}

	mac802154_finalize(xw);

	mutex_lock(&xw->priv->phy->pib_lock);
	if (xw->priv->phy->current_channel != xw->chan ||
	    xw->priv->phy->current_page != xw->page) {
		res = xw->priv->ops->set_channel(&xw->priv->hw,
						  xw->page,
						  xw->chan);
		if (res) {
			pr_debug("set_channel failed\n");
			goto out;
		}

		xw->priv->phy->current_channel = xw->chan;
		xw->priv->phy->current_page = xw->page;
	}

	res = xw->priv->ops->xmit(&xw->priv->hw, xw->skb);
	if (res)
		pr_debug("transmission failed\n");

out:
	mutex_unlock(&xw->priv->phy->pib_lock);

early_out:
	/* Restart the netif queue on each sub_if_data object. */
	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &xw->priv->slaves, list)
		netif_wake_queue(sdata->dev);
	rcu_read_unlock();

	dev_kfree_skb(xw->skb);

	kfree(xw);
}

netdev_tx_t mac802154_tx(struct mac802154_sub_if_data *subif, struct sk_buff *skb,
			 u8 page, u8 chan)
{
	struct xmit_work *work;
	struct mac802154_priv *priv = subif->hw;
	struct mac802154_sub_if_data *sdata;

	if (!(priv->phy->channels_supported[page] & (1 << chan))) {
		WARN_ON(1);
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	mac802154_monitors_rx(mac802154_to_priv(&priv->hw), skb);

	if (skb_cow(skb, priv->hw.extra_tx_headroom)) {
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	work = kzalloc(sizeof(struct xmit_work), GFP_ATOMIC);
	if (!work) {
		kfree_skb(skb);
		return NETDEV_TX_BUSY;
	}

	/* Stop the netif queue on each sub_if_data object. */
	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &priv->slaves, list)
		netif_stop_queue(sdata->dev);
	rcu_read_unlock();

	INIT_WORK(&work->work, mac802154_xmit_worker);
	work->skb = skb;
	work->priv = priv;
	work->subif = subif;
	work->page = page;
	work->chan = chan;

	queue_work(priv->dev_workqueue, &work->work);

	return NETDEV_TX_OK;
}
