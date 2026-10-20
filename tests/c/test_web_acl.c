#include <assert.h>
#include <string.h>

#include "tests.h"
#include "web_acl_core.h"

void test_web_acl_patterns(void)
{
    assert(acl_list_allows("box.view, tonie.*", "box.view"));
    assert(acl_list_allows("box.view, tonie.*", "tonie.assign"));
    assert(!acl_list_allows("box.view, tonie.*", "box.settings"));
    assert(acl_list_allows("*", "folder.write"));
    assert(!acl_list_allows("", "box.view"));
    assert(!acl_list_allows(NULL, "box.view"));
    /* single settings and groups */
    assert(acl_list_allows("box.setting:cloud.*", "box.setting:cloud.enabled"));
    assert(!acl_list_allows("box.setting:cloud.*", "box.setting:core.flex_uid"));
    assert(acl_list_allows("box.settings", "box.setting:core.flex_uid"));
    assert(acl_list_allows("box.setting:toniebox.max_vol_spk", "box.setting:toniebox.max_vol_spk"));
    assert(!acl_list_allows("box.setting:toniebox.max_vol_spk", "box.setting:toniebox.max_vol_hdp"));
    /* "box.vie" is no prefix match */
    assert(!acl_list_allows("box.vie", "box.view"));

    assert(acl_list_within("box.view", "box.*"));
    assert(acl_list_within("box.setting:cloud.*", "box.settings"));
    assert(!acl_list_within("box.*", "box.view"));
    assert(!acl_list_within("*", "box.*"));
    assert(acl_list_within("tonie.view, tonie.assign", "*"));

    assert(acl_lists_overlap("box.*", "box.cfw"));
    assert(acl_lists_overlap("*", "folder.write"));
    assert(acl_lists_overlap("box.setting:*", "box.setting:toniebox.*"));
    assert(acl_lists_overlap("box.settings", "box.setting:core.flex_uid"));
    assert(acl_lists_overlap("box.setting:toniebox.max*", "box.setting:toniebox.*"));
    assert(!acl_lists_overlap("box.setting:cloud.*", "box.setting:toniebox.*"));
    assert(!acl_lists_overlap("box.view, tonie.view", "box.cfw"));
    assert(!acl_lists_overlap("box.view", ""));

    char bad[40];
    assert(acl_list_valid("box.view, box.setting:cloud.*, tonie.*, *", bad, sizeof(bad)));
    assert(!acl_list_valid("box.view, box.fly", bad, sizeof(bad)) && !strcmp(bad, "box.fly"));
    assert(!acl_list_valid("box.setting:a b", bad, sizeof(bad)));
}

void test_web_acl_decisions(void)
{
    acl_subject_t admin = {ACL_LEVEL_ADMIN, ACL_REL_NONE, NULL, NULL, NULL, NULL};
    assert(acl_allowed(&admin, "system.settings"));
    assert(acl_allowed(&admin, "box.settings"));

    acl_subject_t owner = {ACL_LEVEL_USER, ACL_REL_OWNER, NULL, "*", NULL, NULL};
    assert(acl_allowed(&owner, "box.settings"));
    assert(acl_allowed(&owner, "box.setting:cloud.enabled"));
    assert(!acl_allowed(&owner, "system.settings")); /* admin only, never by ownership */

    /* the admin restricts a level-1 user */
    owner.user_deny = "box.cfw, box.setting:core.*";
    assert(!acl_allowed(&owner, "box.cfw"));
    assert(!acl_allowed(&owner, "box.setting:core.flex_uid"));
    assert(acl_allowed(&owner, "box.setting:toniebox.max_vol_spk"));
    /* and the level as a whole */
    owner.user_deny = NULL;
    owner.level_max = "box.*, tonie.*";
    assert(acl_allowed(&owner, "box.view"));
    assert(!acl_allowed(&owner, "folder.write"));

    acl_subject_t shared = {ACL_LEVEL_USER, ACL_REL_SHARED, "box.view, box.setting:toniebox.*", "*", NULL, NULL};
    assert(acl_allowed(&shared, "box.view"));
    assert(acl_allowed(&shared, "box.setting:toniebox.max_vol_spk"));
    assert(!acl_allowed(&shared, "box.settings"));
    assert(!acl_allowed(&shared, "box.share"));

    /* a guest gets at most the guest level, even if more is shared */
    acl_subject_t guest = {ACL_LEVEL_GUEST, ACL_REL_SHARED, "*", "box.view, tonie.view, tonie.assign, folder.read", NULL, NULL};
    assert(acl_allowed(&guest, "tonie.assign"));
    assert(!acl_allowed(&guest, "box.settings"));
    /* guests can not own */
    guest.relation = ACL_REL_OWNER;
    guest.granted = NULL;
    assert(!acl_allowed(&guest, "box.view"));

    acl_subject_t nobody = {ACL_LEVEL_USER, ACL_REL_NONE, "*", "*", NULL, "*"};
    assert(!acl_allowed(&nobody, "box.view"));
    acl_subject_t unassigned = {ACL_LEVEL_USER, ACL_REL_UNASSIGNED, NULL, "*", NULL, "tonie.view, tonie.assign"};
    assert(acl_allowed(&unassigned, "tonie.assign"));
    assert(!acl_allowed(&unassigned, "tonie.share"));

    assert(acl_may_manage_level(ACL_LEVEL_USER, ACL_LEVEL_USER));
    assert(acl_may_manage_level(ACL_LEVEL_USER, ACL_LEVEL_GUEST));
    assert(!acl_may_manage_level(ACL_LEVEL_USER, ACL_LEVEL_ADMIN));
    assert(!acl_may_manage_level(ACL_LEVEL_GUEST, ACL_LEVEL_USER));

    acl_level_t l;
    assert(acl_level_parse("guest", &l) && l == ACL_LEVEL_GUEST);
    assert(!acl_level_parse("root", &l));
}

void test_web_acl_paths(void)
{
    char out[64];
    assert(acl_path_normalize("/by/audioID//123/", out, sizeof(out)) && !strcmp(out, "by/audioID/123"));
    assert(acl_path_normalize("./a/./b", out, sizeof(out)) && !strcmp(out, "a/b"));
    assert(acl_path_normalize("", out, sizeof(out)) && !strcmp(out, ""));
    assert(acl_path_normalize("a\\b", out, sizeof(out)) && !strcmp(out, "a/b"));
    assert(!acl_path_normalize("a/../../etc", out, sizeof(out)));
    assert(!acl_path_normalize("..", out, sizeof(out)));
    assert(acl_path_within("private/alice/x", "private/alice"));
    assert(acl_path_within("private/alice", "private/alice"));
    assert(!acl_path_within("private/alicex", "private/alice"));
    assert(acl_path_within("anything", ""));
}
