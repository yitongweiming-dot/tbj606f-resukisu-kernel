#ifndef __KSU_H_SEPOLICY
#define __KSU_H_SEPOLICY

#include <linux/types.h>

#include "ss/policydb.h"
#include "ss/services.h"

/*
 * Linux 4.19 has no struct selinux_policy: policydb, sidtab and the class
 * mapping all live directly in struct selinux_ss. KSU needs a detached
 * policy it can mutate before publishing, so carry the two pieces that
 * actually change (policydb + sidtab) in our own container. The class
 * mapping is left untouched because KSU never adds classes.
 */
struct ksu_policy_419 {
    struct policydb policydb;
    struct sidtab *sidtab;
};

struct ksu_policy_419 *ksu_dup_sepolicy_419(struct selinux_ss *old_ss);

void ksu_destroy_sepolicy_419(struct ksu_policy_419 *pol);

// Operation on types
bool ksu_type(struct policydb *db, const char *name, const char *attr);
bool ksu_attribute(struct policydb *db, const char *name);
bool ksu_permissive(struct policydb *db, const char *type);
bool ksu_enforce(struct policydb *db, const char *type);
bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr);
bool ksu_exists(struct policydb *db, const char *type);

// Return 1 when the type value is from the initial policy, 0 when it is not, and -1 when metadata is unavailable
int ksu_type_is_original(struct policydb *db, u32 policy_generation, u32 type_value);
bool ksu_set_original_types(struct policydb *db, struct policydb *orig_db, u32 policy_generation);
bool ksu_advance_original_types(struct policydb *db, struct policydb *old_db, u32 old_policy_generation,
                                u32 policy_generation);

// Access vector rules
bool ksu_allow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_deny(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);

// Extended permissions access vector rules
bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);
bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);
bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);

// Type rules
bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def,
                         const char *obj);
bool ksu_type_change(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def);
bool ksu_type_member(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def);

// File system labeling
bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *ctx);

#endif
