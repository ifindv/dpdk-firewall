#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "json.h"

json_object *JR(const char *path, const char *name) {
  char f[MAX_FILE_PATH] = {0};
  if (!path || !name)
    return NULL;
  if (strlen(path) + strlen(name) > (MAX_FILE_PATH - 1))
    return NULL;
  sprintf(f, "%s/%s", path, name);
  return json_object_from_file(f);
}

void JR_FREE(json_object *jr) {
  if (jr)
    json_object_put(jr);
}

int JR_SAVE(const char *path, const char *name, json_object *jr) {
  char f[MAX_FILE_PATH] = {0};
  if (!path || !name || !jr)
    return -1;
  if (strlen(path) + strlen(name) > (MAX_FILE_PATH - 1))
    return -1;
  sprintf(f, "%s/%s", path, name);
  return json_object_to_file(f, jr);
}

int JA(json_object *jr, const char *tag, json_object **ja) {
  if (!jr || !tag)
    return -1;
  if (!json_object_object_get_ex(jr, tag, ja))
    return -1;
  return json_object_array_length(*ja);
}

int JA_ADD(json_object *ja, json_object *jo) {
  if (!ja || !jo)
    return -1;
  return json_object_array_add(ja, jo);
}

int JA_DEL(struct json_object *ja, size_t idx, size_t count) {
  if (!ja)
    return -1;
  return json_object_array_del_idx(ja, idx, count);
}

json_object *JO(json_object *ja, int index) {
  if (!ja)
    return NULL;
  return json_object_array_get_idx(ja, index);
}

json_object *JO_NEW(void) { return json_object_new_object(); }

int JO_ADD(json_object *jo, const char *key, json_object *val) {
  if (!jo || !key || !val)
    return -1;
  return json_object_object_add(jo, key, val);
}

void JO_DEL(struct json_object *jo, const char *key) {
  return json_object_object_del(jo, key);
}

int JO_SET(json_object *jo, const char *val) {
  if (!jo || !val)
    return 0;
  return json_object_set_string(jo, val);
}

json_object *JV(json_object *jo, const char *tag) {
  json_object *jv;
  if (!jo || !tag)
    return NULL;
  if (!json_object_object_get_ex(jo, tag, &jv)) {
    return NULL;
  }
  return jv;
}

int JV_I(json_object *jv) { return json_object_get_int(jv); }

const char *JV_S(json_object *jv) { return json_object_get_string(jv); }

json_object *JV_NEW(const char *val) { return json_object_new_string(val); }

// file format utf-8
// ident using space