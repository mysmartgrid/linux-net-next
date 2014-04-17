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

#include <linux/err.h>
#include <linux/bug.h>
#include <linux/completion.h>
#include <net/ieee802154.h>

#include "mac802154.h"
#include "llsec.h"

void mac802154_llsec_init(struct mac802154_llsec *sec)
{
	memset(sec, 0, sizeof(*sec));

	memset(&sec->params.default_key_source, 0xFF, IEEE802154_ADDR_LEN);

	INIT_LIST_HEAD(&sec->table.security_levels);
	INIT_LIST_HEAD(&sec->table.devices);
	INIT_LIST_HEAD(&sec->table.keys);
	hash_init(sec->devices_short);
	hash_init(sec->devices_hw);
	spin_lock_init(&sec->lock);
}

void mac802154_llsec_destroy(struct mac802154_llsec *sec)
{
	struct ieee802154_llsec_seclevel *sl, *sn;
	struct ieee802154_llsec_device *dev, *dn;
	struct ieee802154_llsec_key_entry *key, *kn;

	list_for_each_entry_safe(sl, sn, &sec->table.security_levels, list) {
		struct mac802154_llsec_seclevel *msl;

		msl = container_of(sl, struct mac802154_llsec_seclevel, level);
		list_del(&sl->list);
		kfree(msl);
	}

	list_for_each_entry_safe(dev, dn, &sec->table.devices, list) {
		struct mac802154_llsec_device *mdev;

		mdev = container_of(dev, struct mac802154_llsec_device, dev);
		list_del(&dev->list);
		kfree(mdev);
	}

	list_for_each_entry_safe(key, kn, &sec->table.keys, list) {
		struct mac802154_llsec_key *mkey;

		mkey = container_of(key->key, struct mac802154_llsec_key, key);
		list_del(&key->list);
		llsec_key_put(mkey);
		kfree(key);
	}
}



int mac802154_llsec_get_params(struct mac802154_llsec *sec,
			       struct ieee802154_llsec_params *params)
{
	spin_lock(&sec->lock);
	*params = sec->params;
	spin_unlock(&sec->lock);

	return 0;
}

int mac802154_llsec_set_params(struct mac802154_llsec *sec,
			       const struct ieee802154_llsec_params *params,
			       int changed)
{
	struct mac802154_llsec_key *key = NULL;
	struct ieee802154_llsec_key_entry *pos;

	list_for_each_entry(pos, &sec->table.keys, list) {
		if (llsec_key_id_equal(&pos->id, &params->out_key)) {
			key = container_of(pos->key, struct mac802154_llsec_key,
					   key);
			break;
		}
	}

	if (!key)
		return -ENOENT;

	spin_lock(&sec->lock);

	if (changed & IEEE802154_LLSEC_PARAM_ENABLED)
		sec->params.enabled = params->enabled;
	if (changed & IEEE802154_LLSEC_PARAM_FRAME_COUNTER)
		sec->params.frame_counter = params->frame_counter;
	if (changed & IEEE802154_LLSEC_PARAM_OUT_LEVEL)
		sec->params.out_level = params->out_level;
	if (changed & IEEE802154_LLSEC_PARAM_OUT_KEY) {
		sec->params.out_key = params->out_key;
		sec->out_key = key;
	}
	if (changed & IEEE802154_LLSEC_PARAM_KEY_SOURCE)
		sec->params.default_key_source = params->default_key_source;
	if (changed & IEEE802154_LLSEC_PARAM_PAN_ID)
		sec->params.pan_id = params->pan_id;
	if (changed & IEEE802154_LLSEC_PARAM_HWADDR)
		sec->params.hwaddr = params->hwaddr;
	if (changed & IEEE802154_LLSEC_PARAM_COORD_HWADDR)
		sec->params.coord_hwaddr = params->coord_hwaddr;
	if (changed & IEEE802154_LLSEC_PARAM_COORD_SHORTADDR)
		sec->params.coord_shortaddr = params->coord_shortaddr;

	spin_unlock(&sec->lock);

	return 0;
}
