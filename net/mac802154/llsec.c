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

static void llsec_key_put(struct mac802154_llsec_key *key);
static bool llsec_key_id_equal(const struct ieee802154_llsec_key_id *a,
			       const struct ieee802154_llsec_key_id *b);

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



static struct mac802154_llsec_key*
llsec_key_alloc(const u8 *key_bytes)
{
	static const int authsizes[3] = { 4, 8, 16 };
	struct mac802154_llsec_key *key;
	int i;

	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return NULL;

	kref_init(&key->ref);
	memcpy(key->key.key, key_bytes, IEEE802154_LLSEC_KEY_SIZE);

	BUILD_BUG_ON(ARRAY_SIZE(authsizes) != ARRAY_SIZE(key->tfm));

	for (i = 0; i < ARRAY_SIZE(key->tfm); i++) {
		key->tfm[i] = crypto_alloc_aead("ccm(aes)", 0,
						CRYPTO_ALG_ASYNC);
		if (!key->tfm[i])
			goto err_tfm;
		if (crypto_aead_setkey(key->tfm[i], key_bytes,
				       IEEE802154_LLSEC_KEY_SIZE))
			goto err_tfm;
		if (crypto_aead_setauthsize(key->tfm[i], authsizes[i]))
			goto err_tfm;
	}

	key->tfm0 = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
	if (!key->tfm0)
		goto err_tfm;

	if (crypto_blkcipher_setkey(key->tfm0, key_bytes,
				    IEEE802154_LLSEC_KEY_SIZE))
		goto err_tfm0;

	return key;

err_tfm0:
	crypto_free_blkcipher(key->tfm0);
err_tfm:
	for (i = 0; i < ARRAY_SIZE(key->tfm); i++)
		if (key->tfm[i])
			crypto_free_aead(key->tfm[i]);

	kfree(key);
	return NULL;
}

static void llsec_key_release(struct kref *ref)
{
	struct mac802154_llsec_key *key;
	int i;

	key = container_of(ref, struct mac802154_llsec_key, ref);

	for (i = 0; i < ARRAY_SIZE(key->tfm); i++)
		crypto_free_aead(key->tfm[i]);

	crypto_free_blkcipher(key->tfm0);
	kfree(key);
}

static struct mac802154_llsec_key*
llsec_key_get(struct mac802154_llsec_key *key)
{
	kref_get(&key->ref);
	return key;
}

static void llsec_key_put(struct mac802154_llsec_key *key)
{
	kref_put(&key->ref, llsec_key_release);
}

static bool llsec_key_id_equal(const struct ieee802154_llsec_key_id *a,
			       const struct ieee802154_llsec_key_id *b)
{
	if (a->mode != b->mode)
		return false;

	if (a->mode == IEEE802154_SCF_KEY_IMPLICIT)
		return ieee802154_addr_equal(&a->device_addr, &b->device_addr);

	if (a->id != b->id)
		return false;

	switch (a->mode) {
	case IEEE802154_SCF_KEY_SHORT_INDEX:
		return a->short_source == b->short_source;
	case IEEE802154_SCF_KEY_HW_INDEX:
		return a->extended_source == b->extended_source;
	}

	return true;
}

int mac802154_llsec_key_add(struct mac802154_llsec *sec,
			    const struct ieee802154_llsec_key_id *id,
			    const struct ieee802154_llsec_key *key)
{
	struct mac802154_llsec_key *mkey = NULL;
	struct ieee802154_llsec_key_entry *pos, *new;

	if (!(key->frame_types & (1 << IEEE802154_FC_TYPE_MAC_CMD)) &&
	    key->cmd_frame_ids)
		return -EINVAL;

	list_for_each_entry(pos, &sec->table.keys, list) {
		if (llsec_key_id_equal(&pos->id, id))
			return -EEXIST;

		if (memcmp(pos->key->key, key->key,
			   IEEE802154_LLSEC_KEY_SIZE))
			continue;

		mkey = container_of(pos->key, struct mac802154_llsec_key, key);

		if (pos->key->frame_types != key->frame_types ||
		    pos->key->cmd_frame_ids != key->cmd_frame_ids)
			return -EEXIST;

		break;
	}

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	if (!key)
		mkey = llsec_key_alloc(key->key);
	else
		mkey = llsec_key_get(mkey);

	if (!mkey)
		goto fail;

	new->id = *id;
	new->key = &mkey->key;

	list_add_rcu(&new->list, &sec->table.keys);

	return 0;

fail:
	kfree(new);
	return -ENOMEM;
}

int mac802154_llsec_key_del(struct mac802154_llsec *sec,
			    const struct ieee802154_llsec_key_id *key)
{
	struct ieee802154_llsec_key_entry *pos;

	list_for_each_entry(pos, &sec->table.keys, list) {
		struct mac802154_llsec_key *mkey;

		mkey = container_of(pos->key, struct mac802154_llsec_key, key);

		if (llsec_key_id_equal(&pos->id, key)) {
			llsec_key_put(mkey);
			return 0;
		}
	}

	return -ENOENT;
}
