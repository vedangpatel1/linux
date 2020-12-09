// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Intel Corporation. */

#include <linux/btf.h>

#include "igc.h"
#include "igc_xdp.h"

#define BTF_INFO_ENC(kind, kind_flag, vlen)			\
	((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))

#define BTF_TYPE_ENC(name, info, size_or_type)	\
	(name), (info), (size_or_type)

#define BTF_INT_ENC(encoding, bits_offset, nr_bits)	\
	((encoding) << 24 | (bits_offset) << 16 | (nr_bits))

#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz)	\
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz),	\
	BTF_INT_ENC(encoding, bits_offset, bits)

#define BTF_STRUCT_ENC(name, nr_elems, sz)	\
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_STRUCT, 1, nr_elems), sz)

#define BTF_MEMBER_ENC(name, type, bits_offset)	\
	(name), (type), (bits_offset)

/* struct xdp_md_desc {
 *	u64 timestamp;
 * };
 */
#define IGC_MD_NUM_MMBRS 1
static const char names_str[] = "\0xdp_md_desc\0timestamp\0";

/* Must match struct xdp_md_desc */
static const u32 igc_md_raw_types[] = {
	/* #define u64 */
	BTF_TYPE_INT_ENC(0, 0, 0, 64, 8),         /* type [1] */
	/* struct xdp_md_desc { */
	BTF_STRUCT_ENC(1, IGC_MD_NUM_MMBRS, 8),
		BTF_MEMBER_ENC(13, 1, 0),    /* u64 timestamp;    */
	/* } */
};

static int igc_xdp_register_btf(struct igc_adapter *priv)
{
	unsigned int type_sec_sz, str_sec_sz;
	char *types_sec, *str_sec;
	struct btf_header *hdr;
	unsigned int btf_size;
	void *raw_btf = NULL;
	int err = 0;

	type_sec_sz = sizeof(igc_md_raw_types);
	str_sec_sz  = sizeof(names_str);

	btf_size = sizeof(*hdr) + type_sec_sz + str_sec_sz;
	raw_btf = kzalloc(btf_size, GFP_KERNEL);
	if (!raw_btf)
		return -ENOMEM;

	hdr = raw_btf;
	hdr->magic    = BTF_MAGIC;
	hdr->version  = BTF_VERSION;
	hdr->hdr_len  = sizeof(*hdr);
	hdr->type_off = 0;
	hdr->type_len = type_sec_sz;
	hdr->str_off  = type_sec_sz;
	hdr->str_len  = str_sec_sz;

	types_sec = raw_btf   + sizeof(*hdr);
	str_sec   = types_sec + type_sec_sz;
	memcpy(types_sec, igc_md_raw_types, type_sec_sz);
	memcpy(str_sec, names_str, str_sec_sz);

	priv->btf = btf_register(priv->netdev->name, raw_btf, btf_size);
	if (IS_ERR(priv->btf)) {
		err = PTR_ERR(priv->btf);
		priv->btf = NULL;
		netdev_err(priv->netdev, "failed to register BTF MD, err (%d)\n", err);
	}

	kfree(raw_btf);
	return err;
}

int igc_xdp_query_btf(struct net_device *dev, u8 *enabled)
{
	struct igc_adapter *priv = netdev_priv(dev);
	u32 md_btf_id = 0;

	if (!IS_ENABLED(CONFIG_BPF_SYSCALL))
		return md_btf_id;

	if (!priv->btf)
		igc_xdp_register_btf(priv);

	*enabled = !!priv->btf_enabled;
	md_btf_id = priv->btf ? btf_obj_id(priv->btf) : 0;

	return md_btf_id;
}

int igc_xdp_set_btf_md(struct net_device *dev, u8 enable)
{
	struct igc_adapter *priv = netdev_priv(dev);
	int err = 0;

	if (enable && !priv->btf) {
		igc_xdp_register_btf(priv);
		if (!priv->btf) {
			err = -EINVAL;
			goto unlock;
		}
	}

	priv->btf_enabled = enable;
unlock:
	return err;
}

int igc_xdp_set_prog(struct igc_adapter *adapter, struct bpf_prog *prog,
		     struct netlink_ext_ack *extack)
{
	struct net_device *dev = adapter->netdev;
	bool if_running = netif_running(dev);
	struct bpf_prog *old_prog;

	if (dev->mtu > ETH_DATA_LEN) {
		/* For now, the driver doesn't support XDP functionality with
		 * jumbo frames so we return error.
		 */
		NL_SET_ERR_MSG_MOD(extack, "Jumbo frames not supported");
		return -EOPNOTSUPP;
	}

	if (if_running)
		igc_close(dev);

	old_prog = xchg(&adapter->xdp_prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	if (if_running)
		igc_open(dev);

	return 0;
}

int igc_xdp_register_rxq_info(struct igc_ring *ring)
{
	struct net_device *dev = ring->netdev;
	int err;

	err = xdp_rxq_info_reg(&ring->xdp_rxq, dev, ring->queue_index, 0);
	if (err) {
		netdev_err(dev, "Failed to register xdp rxq info\n");
		return err;
	}

	err = xdp_rxq_info_reg_mem_model(&ring->xdp_rxq, MEM_TYPE_PAGE_SHARED,
					 NULL);
	if (err) {
		netdev_err(dev, "Failed to register xdp rxq mem model\n");
		xdp_rxq_info_unreg(&ring->xdp_rxq);
		return err;
	}

	return 0;
}

void igc_xdp_unregister_rxq_info(struct igc_ring *ring)
{
	xdp_rxq_info_unreg(&ring->xdp_rxq);
}
