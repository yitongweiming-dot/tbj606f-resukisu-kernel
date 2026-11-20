// SPDX-License-Identifier: GPL-2.0
/*
 * KernelSU sepolicy patching for Linux 4.19 (non-GKI).
 *
 * 4.19 layout differences vs 5.x:
 *   - avtab.htable is a flex_array of struct avtab_node * slots
 *   - policydb.type_attr_map_array is a flex_array of struct ebitmap values
 *   - policydb.type_val_to_struct_array is a flex_array of type_datum pointers
 *   - policydb.sym_val_to_name[SYM_TYPES] is a flex_array of char pointers
 *   - there is no struct selinux_policy; state lives in struct selinux_ss
 *   - symtab_search() helper does not exist, use hashtab_search()
 *
 * We patch the live policydb in place (append only) instead of duplicating
 * the whole policy, so no sidtab rebuild is required.
 */

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/flex_array.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>

#include "ss/avtab.h"
#include "ss/constraint.h"
#include "ss/ebitmap.h"
#include "ss/hashtab.h"
#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/symtab.h"

#include "sepolicy.h"
#include "klog.h" // IWYU pragma: keep

//////////////////////////////////////////////////////
// Declaration
//////////////////////////////////////////////////////

static struct avtab_node *get_avtab_node(struct policydb *db, struct avtab_key *key,
                                         struct avtab_extended_perms *xperms);
static bool is_redundant_avtab_node(struct avtab_node *node);
static bool remove_avtab_node(struct policydb *db, struct avtab_node *node);
static bool add_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *p, int effect,
                     bool invert);
static bool add_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt, struct class_datum *cls,
                         struct perm_datum *perm, int effect, bool invert);
static void add_xperm_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt,
                               struct class_datum *cls, uint16_t low, uint16_t high, int effect, bool invert);
static bool add_xperm_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *range,
                           int effect, bool invert);
static bool add_type_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *d, int effect);
static bool add_filename_trans(struct policydb *db, const char *s, const char *t, const char *c, const char *d,
                               const char *o);
static bool add_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *context);
static bool add_type(struct policydb *db, const char *type_name, bool attr);
static bool set_type_state(struct policydb *db, const char *type_name, bool permissive);
static void add_typeattribute_raw(struct policydb *db, struct type_datum *type, struct type_datum *attr);
static bool add_typeattribute(struct policydb *db, const char *type, const char *attr);

static const struct policydb *ksu_original_types_policy;
static u32 ksu_original_types_limit;
static u32 ksu_original_types_generation;

//////////////////////////////////////////////////////
// Implementation
//////////////////////////////////////////////////////

#define strip_av(effect, invert) ((effect == AVTAB_AUDITDENY) == !invert)

#define ksu_hash_for_each(node_ptr, n_slot, cur)                                                                       \
    int i;                                                                                                             \
    for (i = 0; i < (int)(n_slot); ++i)                                                                                \
        for (cur = node_ptr[i]; cur; cur = cur->next)

/* 4.19: struct symtab embeds a struct hashtab * */
#define ksu_hashtab_for_each(htab, cur) ksu_hash_for_each((htab)->htable, (htab)->size, cur)

/* 4.19: flex_array slots hold pointers */
#define avtab_for_each(avtab, cur)                                                                                     \
    int _i;                                                                                                            \
    for (_i = 0; _i < (int)(avtab).nslot; ++_i)                                                                        \
        for (cur = (struct avtab_node *)flex_array_get_ptr((avtab).htable, _i); cur; cur = cur->next)

/* 4.19 has no symtab_insert(); open-code the hashtab insert plus nprim bump */
static int ksu_symtab_insert(struct symtab *s, char *name, void *datum)
{
    int rc = hashtab_insert(s->table, name, datum);
    if (rc)
        return rc;
    s->nprim++;
    return 0;
}

static struct avtab_node *get_avtab_node(struct policydb *db, struct avtab_key *key,
                                         struct avtab_extended_perms *xperms)
{
    struct avtab_node *node;

    /* AVTAB_XPERMS entries are not necessarily unique */
    if (key->specified & AVTAB_XPERMS) {
        bool match = false;
        node = avtab_search_node(&db->te_avtab, key);
        while (node) {
            if ((node->datum.u.xperms->specified == xperms->specified) &&
                (node->datum.u.xperms->driver == xperms->driver)) {
                match = true;
                break;
            }
            node = avtab_search_node_next(node, key->specified);
        }
        if (!match)
            node = NULL;
    } else {
        node = avtab_search_node(&db->te_avtab, key);
    }

    if (!node) {
        struct avtab_datum avdatum;
        memset(&avdatum, 0, sizeof(avdatum));

        /*
         * AUDITDENY, aka DONTAUDIT, are &= assigned, versus |= for
         * others. Initialize the data accordingly.
         */
        if (key->specified & AVTAB_XPERMS) {
            avdatum.u.xperms = xperms;
        } else {
            avdatum.u.data = key->specified == AVTAB_AUDITDENY ? ~0U : 0U;
        }
        /* this is used to get the node - insertion is actually unique */
        node = avtab_insert_nonunique(&db->te_avtab, key, &avdatum);
        if (!node)
            return NULL;

        db->len += sizeof(struct avtab_key) + sizeof(struct avtab_datum);
    }

    return node;
}

static bool is_redundant_avtab_node(struct avtab_node *node)
{
    if (node->key.specified & AVTAB_XPERMS)
        return node->datum.u.xperms == NULL;
    if (!(node->key.specified & AVTAB_AV))
        return false;
    if (node->key.specified & AVTAB_AUDITDENY)
        return node->datum.u.data == ~0U;
    return node->datum.u.data == 0U;
}

/*
 * In-place patching never needs to drop a node: every rule we add sets bits,
 * so is_redundant_avtab_node() cannot become true for the ALLOWED avtab.
 */
static bool remove_avtab_node(struct policydb *db, struct avtab_node *node)
{
    (void)db;
    (void)node;
    return true;
}

static bool add_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *p, int effect,
                     bool invert)
{
    struct type_datum *src = NULL, *tgt = NULL;
    struct class_datum *cls = NULL;
    struct perm_datum *perm = NULL;

    if (s) {
        src = (struct type_datum *)hashtab_search(db->p_types.table, s);
        if (src == NULL) {
            pr_info("source type %s does not exist\n", s);
            return false;
        }
    }

    if (t) {
        tgt = (struct type_datum *)hashtab_search(db->p_types.table, t);
        if (tgt == NULL) {
            pr_info("target type %s does not exist\n", t);
            return false;
        }
    }

    if (c) {
        cls = (struct class_datum *)hashtab_search(db->p_classes.table, c);
        if (cls == NULL) {
            pr_info("class %s does not exist\n", c);
            return false;
        }
    }

    if (p) {
        if (c == NULL) {
            pr_info("No class is specified, cannot add perm [%s] \n", p);
            return false;
        }

        perm = (struct perm_datum *)hashtab_search(cls->permissions.table, p);
        if (perm == NULL && cls->comdatum != NULL) {
            perm = (struct perm_datum *)hashtab_search(cls->comdatum->permissions.table, p);
        }
        if (perm == NULL) {
            pr_info("perm %s does not exist in class %s\n", p, c);
            return false;
        }
    }
    return add_rule_raw(db, src, tgt, cls, perm, effect, invert);
}

static bool add_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt, struct class_datum *cls,
                         struct perm_datum *perm, int effect, bool invert)
{
    bool success = true;

    if (src == NULL) {
        struct hashtab_node *node;
        if (strip_av(effect, invert)) {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                success &= add_rule_raw(db, (struct type_datum *)node->datum, tgt, cls, perm, effect, invert);
            };
        } else {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                struct type_datum *type = (struct type_datum *)(node->datum);
                if (type->attribute) {
                    success &= add_rule_raw(db, type, tgt, cls, perm, effect, invert);
                }
            };
        }
    } else if (tgt == NULL) {
        struct hashtab_node *node;
        if (strip_av(effect, invert)) {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                success &= add_rule_raw(db, src, (struct type_datum *)node->datum, cls, perm, effect, invert);
            };
        } else {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                struct type_datum *type = (struct type_datum *)(node->datum);
                if (type->attribute) {
                    success &= add_rule_raw(db, src, type, cls, perm, effect, invert);
                }
            };
        }
    } else if (cls == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_classes.table, node)
        {
            success &= add_rule_raw(db, src, tgt, (struct class_datum *)node->datum, perm, effect, invert);
        }
    } else {
        struct avtab_key key;
        struct avtab_node *node;

        memset(&key, 0, sizeof(key));
        key.source_type = src->value;
        key.target_type = tgt->value;
        key.target_class = cls->value;
        key.specified = effect;

        if (invert && effect != AVTAB_AUDITDENY) {
            node = avtab_search_node(&db->te_avtab, &key);
            if (!node)
                return true;
        } else {
            node = get_avtab_node(db, &key, NULL);
            if (!node)
                return false;
        }

        if (invert) {
            if (perm)
                node->datum.u.data &= ~(1U << (perm->value - 1));
            else
                node->datum.u.data = 0U;
        } else {
            if (perm)
                node->datum.u.data |= 1U << (perm->value - 1);
            else
                node->datum.u.data = ~0U;
        }
        if (is_redundant_avtab_node(node))
            return remove_avtab_node(db, node);
    }

    return success;
}

#define ioctl_driver(x) (x >> 8 & 0xFF)
#define ioctl_func(x) (x & 0xFF)

#define xperm_test(x, p) (1 & (p[x >> 5] >> (x & 0x1f)))
#define xperm_set(x, p) (p[x >> 5] |= (1 << (x & 0x1f)))
#define xperm_clear(x, p) (p[x >> 5] &= ~(1 << (x & 0x1f)))

static void add_xperm_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt,
                               struct class_datum *cls, uint16_t low, uint16_t high, int effect, bool invert)
{
    if (src == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            struct type_datum *type = (struct type_datum *)(node->datum);
            if (type->attribute) {
                add_xperm_rule_raw(db, type, tgt, cls, low, high, effect, invert);
            }
        };
    } else if (tgt == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            struct type_datum *type = (struct type_datum *)(node->datum);
            if (type->attribute) {
                add_xperm_rule_raw(db, src, type, cls, low, high, effect, invert);
            }
        };
    } else if (cls == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_classes.table, node)
        {
            add_xperm_rule_raw(db, src, tgt, (struct class_datum *)(node->datum), low, high, effect, invert);
        };
    } else {
        struct avtab_key key;
        struct avtab_datum *datum;
        struct avtab_node *node;
        struct avtab_extended_perms xperms;
        int i;

        memset(&key, 0, sizeof(key));
        key.source_type = src->value;
        key.target_type = tgt->value;
        key.target_class = cls->value;
        key.specified = effect;

        memset(&xperms, 0, sizeof(xperms));
        if (ioctl_driver(low) != ioctl_driver(high)) {
            xperms.specified = AVTAB_XPERMS_IOCTLDRIVER;
            xperms.driver = 0;
        } else {
            xperms.specified = AVTAB_XPERMS_IOCTLFUNCTION;
            xperms.driver = ioctl_driver(low);
        }
        if (xperms.specified == AVTAB_XPERMS_IOCTLDRIVER) {
            for (i = ioctl_driver(low); i <= ioctl_driver(high); ++i) {
                if (invert)
                    xperm_clear(i, xperms.perms.p);
                else
                    xperm_set(i, xperms.perms.p);
            }
        } else {
            for (i = ioctl_func(low); i <= ioctl_func(high); ++i) {
                if (invert)
                    xperm_clear(i, xperms.perms.p);
                else
                    xperm_set(i, xperms.perms.p);
            }
        }

        node = get_avtab_node(db, &key, &xperms);
        if (!node) {
            pr_warn("add_xperm_rule_raw cannot found node!\n");
            return;
        }
        datum = &node->datum;

        /* Allow updating permission bits of existing xperms */
        for (i = 0; i < (int)ARRAY_SIZE(xperms.perms.p); i++)
            datum->u.xperms->perms.p[i] |= xperms.perms.p[i];
    }
}

static bool add_xperm_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *range,
                           int effect, bool invert)
{
    struct type_datum *src = NULL, *tgt = NULL;
    struct class_datum *cls = NULL;
    u16 low, high;

    if (s) {
        src = (struct type_datum *)hashtab_search(db->p_types.table, s);
        if (src == NULL) {
            pr_info("source type %s does not exist\n", s);
            return false;
        }
    }

    if (t) {
        tgt = (struct type_datum *)hashtab_search(db->p_types.table, t);
        if (tgt == NULL) {
            pr_info("target type %s does not exist\n", t);
            return false;
        }
    }

    if (c) {
        cls = (struct class_datum *)hashtab_search(db->p_classes.table, c);
        if (cls == NULL) {
            pr_info("class %s does not exist\n", c);
            return false;
        }
    }

    if (range) {
        if (strchr(range, '-')) {
            sscanf(range, "%hx-%hx", &low, &high);
        } else {
            sscanf(range, "%hx", &low);
            high = low;
        }
    } else {
        low = 0;
        high = 0xFFFF;
    }

    add_xperm_rule_raw(db, src, tgt, cls, low, high, effect, invert);
    return true;
}

static bool add_type_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *d, int effect)
{
    struct type_datum *src, *tgt, *def;
    struct class_datum *cls;
    struct avtab_key key;
    struct avtab_node *node;

    src = (struct type_datum *)hashtab_search(db->p_types.table, s);
    if (src == NULL) {
        pr_info("source type %s does not exist\n", s);
        return false;
    }
    tgt = (struct type_datum *)hashtab_search(db->p_types.table, t);
    if (tgt == NULL) {
        pr_info("target type %s does not exist\n", t);
        return false;
    }
    cls = (struct class_datum *)hashtab_search(db->p_classes.table, c);
    if (cls == NULL) {
        pr_info("class %s does not exist\n", c);
        return false;
    }
    def = (struct type_datum *)hashtab_search(db->p_types.table, d);
    if (def == NULL) {
        pr_info("default type %s does not exist\n", d);
        return false;
    }

    memset(&key, 0, sizeof(key));
    key.source_type = src->value;
    key.target_type = tgt->value;
    key.target_class = cls->value;
    key.specified = effect;

    node = get_avtab_node(db, &key, NULL);
    if (!node)
        return false;
    node->datum.u.data = def->value;

    return true;
}

/* 4.19 filename_trans uses a different policydb layout; not needed by KSU rules */
static bool add_filename_trans(struct policydb *db, const char *s, const char *t, const char *c, const char *d,
                               const char *o)
{
    (void)db;
    (void)s;
    (void)t;
    (void)c;
    (void)d;
    (void)o;
    return true;
}

static bool add_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *context)
{
    (void)db;
    (void)fs_name;
    (void)path;
    (void)context;
    return false;
}

/*
 * 4.19 keeps the type index arrays in flex_array, whose capacity is fixed at
 * allocation time, so growing the policy requires reallocating all three.
 */
static bool add_type(struct policydb *db, const char *type_name, bool attr)
{
    struct type_datum *type;
    struct flex_array *new_map = NULL, *new_tv = NULL, *new_names = NULL;
    struct ebitmap *self_map;
    char *key;
    u32 value;
    int i, rc;

    type = (struct type_datum *)hashtab_search(db->p_types.table, type_name);
    if (type) {
        pr_warn("Type %s already exists\n", type_name);
        return true;
    }

    value = db->p_types.nprim + 1;

    type = (struct type_datum *)kzalloc(sizeof(*type), GFP_KERNEL);
    if (!type) {
        pr_err("add_type: alloc type_datum failed.\n");
        return false;
    }
    type->primary = 1;
    type->value = value;
    type->attribute = attr;

    key = kstrdup(type_name, GFP_KERNEL);
    if (!key) {
        pr_err("add_type: alloc key failed.\n");
        kfree(type);
        return false;
    }

    /* grow type_attr_map_array */
    new_map = flex_array_alloc((int)sizeof(struct ebitmap), value, GFP_KERNEL);
    if (!new_map)
        goto err;
    rc = flex_array_prealloc(new_map, 0, value, GFP_KERNEL);
    if (rc)
        goto err;
    for (i = 0; i < (int)(value - 1); i++) {
        struct ebitmap *src = (struct ebitmap *)flex_array_get(db->type_attr_map_array, i);
        struct ebitmap *dst = (struct ebitmap *)flex_array_get(new_map, i);
        if (!src || !dst)
            goto err;
        memcpy(dst, src, sizeof(struct ebitmap));
    }
    self_map = (struct ebitmap *)flex_array_get(new_map, value - 1);
    if (!self_map)
        goto err;
    ebitmap_init(self_map);
    if (ebitmap_set_bit(self_map, (unsigned long)(value - 1), 1))
        goto err;

    /* grow type_val_to_struct_array */
    new_tv = flex_array_alloc((int)sizeof(struct type_datum *), value, GFP_KERNEL);
    if (!new_tv)
        goto err;
    rc = flex_array_prealloc(new_tv, 0, value, GFP_KERNEL);
    if (rc)
        goto err;
    for (i = 0; i < (int)(value - 1); i++) {
        struct type_datum *ptr = (struct type_datum *)flex_array_get_ptr(db->type_val_to_struct_array, i);
        if (flex_array_put(new_tv, i, &ptr, GFP_KERNEL))
            goto err;
    }
    if (flex_array_put(new_tv, value - 1, &type, GFP_KERNEL))
        goto err;

    /* grow sym_val_to_name[SYM_TYPES] */
    new_names = flex_array_alloc((int)sizeof(char *), value, GFP_KERNEL);
    if (!new_names)
        goto err;
    rc = flex_array_prealloc(new_names, 0, value, GFP_KERNEL);
    if (rc)
        goto err;
    for (i = 0; i < (int)(value - 1); i++) {
        char *name = (char *)flex_array_get_ptr(db->sym_val_to_name[SYM_TYPES], i);
        if (flex_array_put(new_names, i, &name, GFP_KERNEL))
            goto err;
    }
    if (flex_array_put(new_names, value - 1, &key, GFP_KERNEL))
        goto err;

    /* commit */
    if (ksu_symtab_insert(&db->p_types, key, type)) {
        pr_err("add_type: insert symtab failed.\n");
        goto err;
    }

    flex_array_free(db->type_attr_map_array);
    db->type_attr_map_array = new_map;
    flex_array_free(db->type_val_to_struct_array);
    db->type_val_to_struct_array = new_tv;
    flex_array_free(db->sym_val_to_name[SYM_TYPES]);
    db->sym_val_to_name[SYM_TYPES] = new_names;

    if (db->role_val_to_struct) {
        for (i = 0; i < (int)db->p_roles.nprim; ++i) {
            struct role_datum *role = db->role_val_to_struct[i];
            if (role)
                ebitmap_set_bit(&role->types, (unsigned long)(value - 1), 1);
        }
    }

    pr_info("add_type: %s -> %u (attr=%d)\n", type_name, value, attr);
    return true;

err:
    pr_err("add_type: grow policy failed for %s\n", type_name);
    if (new_map)
        flex_array_free(new_map);
    if (new_tv)
        flex_array_free(new_tv);
    if (new_names)
        flex_array_free(new_names);
    kfree(key);
    kfree(type);
    return false;
}

static bool set_type_state(struct policydb *db, const char *type_name, bool permissive)
{
    struct type_datum *type;
    if (type_name == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            type = (struct type_datum *)(node->datum);
            if (ebitmap_set_bit(&db->permissive_map, type->value, permissive))
                pr_info("Could not set bit in permissive map\n");
        };
    } else {
        type = (struct type_datum *)hashtab_search(db->p_types.table, type_name);
        if (type == NULL) {
            pr_info("type %s does not exist\n", type_name);
            return false;
        }
        if (ebitmap_set_bit(&db->permissive_map, type->value, permissive)) {
            pr_info("Could not set bit in permissive map\n");
            return false;
        }
    }
    return true;
}

static void add_typeattribute_raw(struct policydb *db, struct type_datum *type, struct type_datum *attr)
{
    struct ebitmap *sattr = (struct ebitmap *)flex_array_get(db->type_attr_map_array, type->value - 1);
    struct hashtab_node *node;
    struct constraint_node *n;
    struct constraint_expr *e;

    if (!sattr) {
        pr_err("add_typeattribute_raw: type_attr_map missing for %u\n", type->value);
        return;
    }
    ebitmap_set_bit(sattr, (unsigned long)(attr->value - 1), 1);

    ksu_hashtab_for_each(db->p_classes.table, node)
    {
        struct class_datum *cls = (struct class_datum *)(node->datum);
        for (n = cls->constraints; n; n = n->next) {
            for (e = n->expr; e; e = e->next) {
                if (e->expr_type == CEXPR_NAMES && ebitmap_get_bit(&e->type_names->types, attr->value - 1)) {
                    ebitmap_set_bit(&e->names, (unsigned long)(type->value - 1), 1);
                }
            }
        }
    };
}

static bool add_typeattribute(struct policydb *db, const char *type, const char *attr)
{
    struct type_datum *type_d = (struct type_datum *)hashtab_search(db->p_types.table, type);
    struct type_datum *attr_d;

    if (type_d == NULL) {
        pr_info("type %s does not exist\n", type);
        return false;
    } else if (type_d->attribute) {
        pr_info("type %s is an attribute\n", attr);
        return false;
    }

    attr_d = (struct type_datum *)hashtab_search(db->p_types.table, attr);
    if (attr_d == NULL) {
        pr_info("attribute %s does not exist\n", type);
        return false;
    } else if (!attr_d->attribute) {
        pr_info("type %s is not an attribute \n", attr);
        return false;
    }

    add_typeattribute_raw(db, type_d, attr_d);
    return true;
}

//////////////////////////////////////////////////////////////////////////

bool ksu_type(struct policydb *db, const char *name, const char *attr)
{
    return add_type(db, name, false) && add_typeattribute(db, name, attr);
}

bool ksu_attribute(struct policydb *db, const char *name)
{
    return add_type(db, name, true);
}

bool ksu_permissive(struct policydb *db, const char *type)
{
    return set_type_state(db, type, true);
}

bool ksu_enforce(struct policydb *db, const char *type)
{
    return set_type_state(db, type, false);
}

bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr)
{
    return add_typeattribute(db, type, attr);
}

bool ksu_exists(struct policydb *db, const char *type)
{
    return hashtab_search(db->p_types.table, type) != NULL;
}

bool ksu_set_original_types(struct policydb *db, struct policydb *orig_db, u32 policy_generation)
{
    if (!db || !orig_db || !policy_generation || orig_db->p_types.nprim > db->p_types.nprim) {
        WRITE_ONCE(ksu_original_types_generation, 0);
        WRITE_ONCE(ksu_original_types_policy, NULL);
        WRITE_ONCE(ksu_original_types_limit, 0);
        return false;
    }

    WRITE_ONCE(ksu_original_types_limit, orig_db->p_types.nprim);
    WRITE_ONCE(ksu_original_types_generation, policy_generation);
    WRITE_ONCE(ksu_original_types_policy, db);
    return true;
}

bool ksu_advance_original_types(struct policydb *db, struct policydb *old_db, u32 old_policy_generation,
                                u32 policy_generation)
{
    u32 original_types_limit = READ_ONCE(ksu_original_types_limit);
    u32 original_types_generation = READ_ONCE(ksu_original_types_generation);

    if (!db || !old_db || !old_policy_generation || !policy_generation || !original_types_limit ||
        !original_types_generation || old_policy_generation != original_types_generation ||
        READ_ONCE(ksu_original_types_policy) != old_db || db->p_types.nprim < original_types_limit) {
        WRITE_ONCE(ksu_original_types_generation, 0);
        WRITE_ONCE(ksu_original_types_policy, NULL);
        WRITE_ONCE(ksu_original_types_limit, 0);
        return false;
    }

    WRITE_ONCE(ksu_original_types_generation, policy_generation);
    WRITE_ONCE(ksu_original_types_policy, db);
    return true;
}

int ksu_type_is_original(struct policydb *db, u32 policy_generation, u32 type_value)
{
    const struct policydb *original_types_policy = READ_ONCE(ksu_original_types_policy);
    u32 original_types_limit = READ_ONCE(ksu_original_types_limit);
    u32 original_types_generation = READ_ONCE(ksu_original_types_generation);

    if (!db || !policy_generation || original_types_policy != db || original_types_generation != policy_generation ||
        !original_types_limit || type_value > db->p_types.nprim)
        return -1;

    return type_value && type_value <= original_types_limit ? 1 : 0;
}

// Access vector rules
bool ksu_allow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_ALLOWED, false);
}

bool ksu_deny(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_ALLOWED, true);
}

bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_AUDITALLOW, false);
}

bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_AUDITDENY, true);
}

// Extended permissions access vector rules
bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_ALLOWED, false);
}

bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_AUDITALLOW, false);
}

bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_DONTAUDIT, false);
}

// Type rules
bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def,
                         const char *obj)
{
    if (obj) {
        return add_filename_trans(db, src, tgt, cls, def, obj);
    } else {
        return add_type_rule(db, src, tgt, cls, def, AVTAB_TRANSITION);
    }
}

bool ksu_type_change(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def)
{
    return add_type_rule(db, src, tgt, cls, def, AVTAB_CHANGE);
}

bool ksu_type_member(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def)
{
    return add_type_rule(db, src, tgt, cls, def, AVTAB_MEMBER);
}

// File system labeling
bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *ctx)
{
    return add_genfscon(db, fs_name, path, ctx);
}

//////////////////////////////////////////////////////////////////////////
// 4.19 policy duplication
//
// security_load_policy() in 4.19 builds the replacement out of line and only
// swaps it in under write_lock_irq(), because avtab_insert_node() allocates
// with GFP_KERNEL and cannot run inside the rwlock. We follow the same
// pattern: serialize the live policydb, parse it back into a private copy,
// mutate that copy, and publish it later.
//////////////////////////////////////////////////////////////////////////

/*
 * 4.19 sidtab_convert() calls params->func() unconditionally while copying
 * every live entry into the new sidtab. Passing a zeroed params struct (as an
 * older revision did) means a NULL indirect call and an instant panic, so we
 * must supply a real callback that just copies the context over.
 */
static int ksu_sidtab_convert_cpy(struct context *oldc, struct context *newc,
                                  void *args, gfp_t gfp_flags)
{
    (void)args;
    (void)gfp_flags;
    return context_cpy(newc, oldc);
}

struct ksu_policy_419 *ksu_dup_sepolicy_419(struct selinux_ss *old_ss)
{
    struct ksu_policy_419 *new_pol;
    struct policy_file fp;
    char *data;
    size_t len, written;
    int ret;

    if (!old_ss || !old_ss->policydb.p_types.nprim || !old_ss->sidtab)
        return ERR_PTR(-EINVAL);

    /*
     * policydb_write() emits every type_attr_map ebitmap, so give the buffer
     * room for the read-back form plus the header/footer slack.
     */
    len = old_ss->policydb.len + 8192;
    len += (size_t)old_ss->policydb.p_types.nprim * (sizeof(u32) + sizeof(u64)) * 2;

    data = vmalloc(len);
    if (!data)
        return ERR_PTR(-ENOMEM);
    memset(data, 0, len);

    fp.data = data;
    fp.len = len;

    ret = policydb_write(&old_ss->policydb, &fp);
    if (ret) {
        pr_err("ksu_dup_sepolicy_419: policydb_write failed: %d\n", ret);
        goto err_free;
    }
    written = len - fp.len;

    new_pol = kzalloc(sizeof(*new_pol), GFP_KERNEL);
    if (!new_pol) {
        ret = -ENOMEM;
        goto err_free;
    }

    fp.data = data;
    fp.len = written;
    ret = policydb_read(&new_pol->policydb, &fp);
    if (ret) {
        pr_err("ksu_dup_sepolicy_419: policydb_read failed: %d\n", ret);
        goto err_pol;
    }
    new_pol->policydb.len = written;

    new_pol->sidtab = kzalloc(sizeof(*new_pol->sidtab), GFP_KERNEL);
    if (!new_pol->sidtab) {
        ret = -ENOMEM;
        goto err_db;
    }

    ret = sidtab_init(new_pol->sidtab);
    if (ret)
        goto err_sidtab;

    ret = policydb_load_isids(&new_pol->policydb, new_pol->sidtab);
    if (ret) {
        pr_err("ksu_dup_sepolicy_419: policydb_load_isids failed: %d\n", ret);
        goto err_sidtab;
    }

    {
        struct sidtab_convert_params params;
        memset(&params, 0, sizeof(params));
        params.func = ksu_sidtab_convert_cpy;
        params.target = new_pol->sidtab;
        ret = sidtab_convert(old_ss->sidtab, &params);
        if (ret) {
            pr_err("ksu_dup_sepolicy_419: sidtab_convert failed: %d\n", ret);
            goto err_sidtab;
        }
    }

    vfree(data);
    pr_info("ksu_dup_sepolicy_419: ok len=%zu types=%u avtab=%u sidtab=%u\n", written,
            new_pol->policydb.p_types.nprim, new_pol->policydb.te_avtab.nel, new_pol->sidtab->count);
    return new_pol;

err_sidtab:
    sidtab_destroy(new_pol->sidtab);
    kfree(new_pol->sidtab);
err_db:
    policydb_destroy(&new_pol->policydb);
err_pol:
    kfree(new_pol);
err_free:
    vfree(data);
    return ERR_PTR(ret);
}

void ksu_destroy_sepolicy_419(struct ksu_policy_419 *pol)
{
    if (!pol)
        return;
    if (pol->sidtab) {
        sidtab_destroy(pol->sidtab);
        kfree(pol->sidtab);
    }
    policydb_destroy(&pol->policydb);
    kfree(pol);
}
