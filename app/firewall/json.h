#ifndef _M_JSON_H_
#define _M_JSON_H_

/** simple encapsulation of lib json-c
 * */

#include <json-c/json.h>

/** Read content from json file to json root
 * @param path
 *  path of json file
 * @param name
 *  name of json file
 * @return
 *  json root pointer on success, NULL for a failure
 * */
json_object *JR(const char *path, const char *name);

/** Free json root alloc by JR()
 * @param
 *  json root alloc by JR()
 * */
void JR_FREE(json_object *jr);

/** Save content of json root to json file
 * @param path
 *  path of json file
 * @param name
 *  name of json file
 * @param jr
 *  the json root
 * @return
 * 	0 on success, -1 for a failure
 * */
int JR_SAVE(const char *path, const char *name, json_object *jr);

/** Get json array from given json root
 * @param jr
 *  the given json root
 * @param tag
 *  tag of which json array to read
 * @param ja
 *  json array pointer
 * @return
 *  number of json object in json array, -1 for a failure
 * */
int JA(json_object *jr, const char *tag, json_object **ja);

/** Add an element to the end of a json_object of type json_type_array
 * The reference count will *not* be incremented.
 * @param ja
 *  the json array
 * @param jo
 *  the json object to be added
 * @param return
 *  0 on success, -1 for a failure
 */
int JA_ADD(json_object *ja, json_object *jo);

/** Delete an elements from a specified index in an array
 *
 * The reference count will be decremented for each of the deleted objects.  If
 * there are no more owners of an element that is being deleted, then the value
 * is freed.  Otherwise, the reference to the value will remain in memory.
 *
 * @param ja
 *  the json array
 * @param idx
 *  the index to start deleting elements at
 * @param count
 *  the number of elements to delete
 * @returns
 *  0 if the elements were successfully deleted
 */
int JA_DEL(struct json_object *ja, size_t idx, size_t count);

/** Get json object from given json array
 * @param ja
 *  the given json array
 * @param index
 *  index of json object to get
 * @return
 *  json object pointer on success, NULL for a failure
 * */
json_object *JO(json_object *ja, int index);

/** Create a new empty object with a reference count of 1
 * */
json_object *JO_NEW(void);

/** Add a json value to json object, of which keyword is 'key'
 * @param jo
 *  the json object
 * @param key
 *  keyword of the json value
 * @param jv
 *  the json value
 * @return
 *  0 on success, negative value for a failure
 * */
int JO_ADD(json_object *jo, const char *key, json_object *jv);

/** Delete the given json object's field, of which keyword is 'key'
 * @param jo
 *  the json object
 * @param key
 *  keyword of the field
 * */
void JO_DEL(struct json_object *jo, const char *key);

/** Set the string value of a json_object with zero terminated strings
 * @returns
 *  1 if value is set correctly, 0 otherwise
 */
int JO_SET(json_object *jo, const char *val);

/** Get json value from given json object
 * @param jo
 *  the given json object
 * @param tag
 *  tag of which json value to read
 * @return
 *  json value pointer on success, NULL for a failure
 * */
json_object *JV(json_object *jo, const char *tag);

/** Get value from JV in various type
 * */
int JV_I(json_object *jv);
const char *JV_S(json_object *jv);

/** Create a new json value object of type string
 * @param val
 * 	value
 * @return
 * 	json value pointer, NULL for a failure
 * */
json_object *JV_NEW(const char *val);

#define JV_SET(jv, val) JO_SET(jv, val)

#endif

// file format utf-8
// ident using space