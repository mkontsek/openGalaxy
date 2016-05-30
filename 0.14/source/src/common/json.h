/* This file is part of openGalaxy.
 *
 * opengalaxy - a SIA receiver for Galaxy security control panels.
 * Copyright (C) 2015 - 2016 Alexander Bruines <alexander.bruines@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * as published by the Free Software Foundation, or (at your option)
 * any later version.
 *
 * In addition, as a special exception, the author of this program
 * gives permission to link the code of its release with the OpenSSL
 * project's "OpenSSL" library (or with modified versions of it that
 * use the same license as the "OpenSSL" library), and distribute the
 * linked executables. You must obey the GNU General Public License
 * in all respects for all of the code used other than "OpenSSL".
 * If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so.
 * If you do not wish to do so, delete this exception statement
 * from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __JSON_PARSER_H__
#define __JSON_PARSER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

// Forward declarations for the data structures

struct json_object_t;
struct json_item_t;
struct json_value_t;
struct json_value_string_t;
struct json_value_number_t;
struct json_value_object_t;
struct json_value_array_t;
struct json_value_boolean_t;
struct json_value_nill_t;

// Now actually declare the data structure types

typedef enum json_value_type_t {        // The diffrent types of items an object may contain:
  json_undefined_value = 0,
  json_string_value,                    //  - the item is a string value
  json_number_value,                    //  - the item is a number value
  json_object_value,                    //  - the item is a(n) (list of) object(s)
  json_array_value,                     //  - the item is an array of items
  json_boolean_value,                   //  - the item is a boolean value
  json_nill_value                       //  - the item is a NULL value
} json_value_type;


typedef struct json_object_t {          // A(n) (list of) object(s):
  struct json_item_t    *items;         //  - the (list of) item(s) in this object
  struct json_object_t  *next;          //  - the next object or NULL
} json_object;


typedef union {                         // item content:
  struct json_value_string_t  *string;  //  - if it is a string
  struct json_value_number_t  *number;  //  - if it is a number
  struct json_value_object_t  *object;  //  - if it is a(n) (list of) object(s)
  struct json_value_array_t   *array;   //  - if it is an array
  struct json_value_boolean_t *boolean; //  - if it is a boolean
  struct json_value_nill_t    *nill;    //  - if it is a NULL value
} json_value_content;


typedef struct json_value_t {           // item value:
  json_value_type             type;     //  - the type of item
  json_value_content          content;  //  - the actual content
} json_value;


typedef struct json_item_t {            // A single name/value pair of an obect
  struct json_value_string_t  *name;    //  - the item name
  struct json_value_t         *data;    //  - the value of the item
  struct json_item_t          *next;    // The next object item or null
} json_item;


typedef struct json_value_string_t {
  char                        *value;   // A string value
  unsigned long int           length;   // Length of string including the \0 byte
} json_value_string;


typedef struct json_value_number_t {
  long int                    value;    // A number value
} json_value_number;


typedef struct json_value_object_t {
  struct json_object_t        *value;   // A(n) (list of) object(s)
} json_value_object;


typedef struct json_value_array_t {
  struct json_value_t         *value;   // A single element of the array
  struct json_value_array_t   *next;    // The next element or NULL
} json_value_array;


typedef struct json_value_boolean_t {
  bool                        value;    // A boolean value
} json_value_boolean;


typedef struct json_value_nill_t {   // A NULL item contains nothing
} json_value_nill;


json_object * json_parse_objects      ( const char       *json );
void          json_print_objects      ( json_object      *objects );
void          json_print_array_values ( json_value_array *array );
void          json_free_objects       ( json_object      *objects );

#ifdef __cplusplus
}
#endif

#endif

