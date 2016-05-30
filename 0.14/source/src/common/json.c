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
   *
   **************************************************************************
   *
   * Simple JSON object parser
   *
   *           ┌─────────────────────────── Object ────────────────────────────┐
   *           │                                                               │
   *           │        ┌─────────────────────>>──────────────────────┐        │
   *           │        │                                             │        │
   *           │        │    ┌─────────── Item ───────────┐           │        │
   *             ┌───┐  │      ┌──────┐  ┌───┐  ┌───────┐             │  ┌───┐
   * ──>>──┬─────┤ { ├──┴──┬───┤ name ├──┤ : ├──┤ value ├──────────┬──┴──┤ } ├──────────┬──>>──
   *       │     └───┘     │   └──────┘  └───┘  └───────┘   ┌───┐  │     └───┘          │
   *       │               └──────────────────<<────────────┤ , ├──┘                    │
   *       │                                                └───┘                ┌───┐  │
   *       └──────────────────────────────────<<─────────────────────────────────┤ , ├──┘
   *                                                                             └───┘
   * Where 'name' is a json_value_string and 'value' may be any json_value_type value.
   *
   *
   *
   *         ┌─────────── Item ───────────┐
   *           ┌──────┐  ┌───┐  ┌───────┐
   * ──>>──┬───┤ name ├──┤ : ├──┤ value ├──────────┬──>>──
   *       │   └──────┘  └───┘  └───────┘   ┌───┐  │
   *       └──────────────────<<────────────┤ , ├──┘
   *                                        └───┘
   *
   *     ┌─────── Value ───────┐
   *           ┌─────────┐
   * ─>>──┬────┤ string  ├─>>─┬───
   *      │    └─────────┘    │
   *      │    ┌─────────┐    │
   *      ├────┤ number  ├─>>─┤
   *      │    └─────────┘    │
   *      │    ┌─────────┐    │
   *      ├────┤ object  ├─>>─┤
   *      │    └─────────┘    │
   *      │    ┌─────────┐    │
   *      ├────┤  array  ├─>>─┤
   *      │    └─────────┘    │
   *      │    ┌─────────┐    │
   *      ├────┤ boolean ├─>>─┤
   *      │    └─────────┘    │
   *      │    ┌─────────┐    │
   *      └────┤  null   ├─>>─┘
   *           └─────────┘
   *
   *        ┌────────────────────────────── String ────────────────────────────────┐
   *        │                                                                      │
   *        │         ┌─────────────────────────>>───────────────────────┐         │
   *        │         │                                                  │         │
   *        │         │  ┌──────────────────────<<────────────────────┐  │         │
   *                  │  │                                            │  │
   *           ┌───┐  │  │      ┌──────────────────────────────┐      │  │  ┌───┐
   *  ──>>─────┤ " ├──┴──┴──┬───┤ Any UNICODE character except ├───┬──┴──┴──┤ " ├─────>>──
   *           └───┘        │   │  " or \ or control character │   │        └───┘
   *                      ┌─┴─┐ └──────────────────────────────┘   │
   *                      │ \ │                                    │
   *                      └─┬─┘ ┌───┐  Quotation mark              │
   *                        ├───┤ " ├───────────────────────────>>─┤
   *                        │   └───┘                              │
   *                        │   ┌───┐  Reverse solidus             │
   *                        ├───┤ \ ├───────────────────────────>>─┤
   *                        │   └───┘                              │
   *                        │   ┌───┐  Solidus                     │
   *                        ├───┤ / ├───────────────────────────>>─┤
   *                        │   └───┘                              │
   *                        │   ┌───┐  Backspace                   │
   *                        ├───┤ b ├───────────────────────────>>─┤
   *                        │   └───┘                              │
   *                        │   ┌───┐  Formfeed                    │
   *                        ├───┤ f ├───────────────────────────>>─┤
   *                        │   └───┘                              │
   *                        │   ┌───┐  Newline                     │
   *                        ├───┤ n ├───────────────────────────>>─┤
   *                        │   └───┘                              │
   *                        │   ┌───┐  Carriage return             │
   *                        ├───┤ r ├───────────────────────────>>─┤
   *                        │   └───┘                              │
   *                        │   ┌───┐  Horizontal tab              │
   *                        ├───┤ t ├───────────────────────────>>─┤
   *                        │   └───┘                              │
   *                        │   ┌───┐  ┌──────────────────────┐    │
   *                        └───┤ u ├──┤ 4 hexadecimal digits ├─>>─┘
   *                            └───┘  └──────────────────────┘
   *  Note: We do not support \uXXXX but the other ones listed here are handled correctly.
   *        Other escaped character are unescaped verbatim.
   *
   *
   *      ┌────────┐
   * ─>>──┤ number ├──>>─
   *      └────────┘
   *  Note: We only support signed integer values in base10.
   *
   *
   *       ┌────────────────── Array ──────────────────┐
   *       │                                           │
   *       │        ┌───────────>>───────────┐         │
   *         ┌───┐  │     ┌───────┐          │  ┌───┐
   * ──>>────┤ [ ├──┴──┬──┤ value ├───────┬──┴──┤ ] ├────>>──
   *         └───┘     │  └───────┘ ┌───┐ │     └───┘
   *                   └────<<──────┤ , ├─┘
   *                                └───┘
   * Where 'value' may be any json_value_type value.
   *
   *
   *    ┌───── Boolean ─────┐
   *    │                   │
   *          ┌───────┐
   * ─>>─┬────┤ true  ├─>>─┬────
   *     │    └───────┘    │
   *     │    ┌───────┐    │
   *     └────┤ false ├─>>─┘
   *          └───────┘
   *
   */

// TODO: don't use recursive function calls, it uses a lot of memory when
// parsing large objects/arrays... (fortunately we only parse small objects)

#include "atomic.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "json.h"

static json_object *        json_parse_object       ( const char *json, int *position );
static json_item *          json_parse_items        ( const char *json, int *position );
static json_value *         json_parse_value        ( const char *json, int *position );
static json_value_string *  json_parse_string_value ( const char *json, int *position );
static json_value_number *  json_parse_number_value ( const char *json, int *position );
static json_value_object *  json_parse_object_value ( const char *json, int *position );
static json_value_array *   json_parse_array_values ( const char *json, int *position );
static json_value_array *   json_parse_array_value  ( const char *json, int *position );
static json_value_boolean * json_parse_boolean_value( const char *json, int *position );
static json_object *        json_new_object         ( void );
static json_item *          json_new_item           ( void );
static json_value *         json_new_value          ( void );
static json_value_string *  json_new_string_value   ( void );
static json_value_number *  json_new_number_value   ( void );
static json_value_object *  json_new_object_value   ( void );
static json_value_array *   json_new_array_value    ( void );
static json_value_boolean * json_new_boolean_value  ( void );
static void                 json_free_items         ( json_item          *items );
static void                 json_free_value         ( json_value         *value );
static void                 json_free_string_value  ( json_value_string  *string );
static void                 json_free_number_value  ( json_value_number  *number );
static void                 json_free_object_value  ( json_value_object  *object );
static void                 json_free_array_values  ( json_value_array   *array );
static void                 json_free_boolean_value ( json_value_boolean *boolean );
static char *               str_unescape            ( char * str );


// Parses a stream of JSON objects
json_object * json_parse_objects( const char *json )
{
  json_object *retv = NULL;
  int pos = 0;

  if( json != NULL ){

    // scan for { while ignoring spaces, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }

    if( json[pos] == '{' ){
      retv = json_parse_object( json, &pos );
    }

  }
  return retv;
}

// Prints the values of an array
void json_print_array_values( json_value_array *array )
{
//  if( array ){
  while( array ){
    if( array->value != NULL ){
      switch( array->value->type ){

        case json_string_value:
          printf( "(string) : %s\n", array->value->content.string->value );
          break;

        case json_number_value:
          printf( "(number) : %ld\n", array->value->content.number->value );
          break;

        case json_object_value:
          printf( "(object) :\n" );
          json_print_objects( array->value->content.object->value );
          break;

        case json_array_value:
          printf( "(array) :\n" );
          json_print_array_values( array->value->content.array );
          break;

        case json_boolean_value:
          printf( "(boolean) : %s\n", ( array->value->content.boolean->value ) ? "true" : "false" );
          break;

        case json_nill_value:
          printf( "(null) : %s\n", (char*)array->value->content.nill );
          break;

        default:
          break;
      }
    }
//    json_print_array_values( array->next );
    array = array->next;
  }
}


// Prints a JSON object or list of objects
void json_print_objects( json_object *objects )
{
  json_object *object = objects;
  json_item *item;

  while( object ){
    puts( "{" );

    item = object->items;
    while( item ){
      printf( "%s " , item->name->value );
      if( item->data ){

        switch( item->data->type ){
          case json_string_value:
            printf( "(string) : %s\n", item->data->content.string->value );
            break;
          case json_number_value:
            printf( "(number) : %ld\n", item->data->content.number->value );
            break;
          case json_object_value:
            printf( "(object) :\n" );
            json_print_objects( item->data->content.object->value );
            break;
          case json_array_value:
            printf( "(array) :\n" );
            json_print_array_values( item->data->content.array );
            break;
          case json_boolean_value:
            printf( "(boolean) : %s\n", ( item->data->content.boolean->value ) ? "true" : "false" );
            break;
          case json_nill_value:
            printf( "(null) : %s\n", (char*)item->data->content.nill );
            break;
          default:
            break;
        }

      }
      item = item->next;
      if( item ) { puts( "," ); }      
    }

    puts( "}" );
    object = object->next;
  }
}


void json_free_objects( json_object *object )
{
  if( object ){
    if( object->next != NULL ) json_free_objects( object->next );
    if( object->items != NULL ) json_free_items( object->items );
    free( object );
  }
}


// parses the Nth JSON object
static json_object * json_parse_object( const char *json, int *position )
{
  json_object *retv = NULL;
  json_item *items = NULL;
  int pos, saved;

  if( json != NULL ){

    // Load current position into pos
    if( position != NULL ){
      pos = *position;
    }
    else {
      pos = 0;
    }

    // Make sure pos is within bounds
    if( ( pos < 0 ) || ( pos >= strlen( json ) ) ){
      pos = -1;
      goto exit;
    }

    saved = pos;

    // scan for { while ignoring spaces, commas, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == ','  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }
    if( json[pos] != '{' ){
      pos = saved; // restore saved position since we did not find an(other) object
      goto exit;
    }
    pos++; // character after {

    // parse the item(s)
    items = json_parse_items( json, &pos );
    if( pos < 0 ){
      // bail out on error
      goto exit;
    }
    if( items != NULL ){
      // we got at least one item, time to create a new object
      retv = json_new_object();
      if( retv == NULL ){
        json_free_items( items );
        items = NULL;
        pos = -1;
        goto exit;
      }
      retv->items = items;
      items = NULL;
    }

    // scan for } while ignoring spaces, commas, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == ','  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }
    if( json[pos] != '}' ){
      json_free_objects( retv );
      retv = NULL;
      pos = -1;
      goto exit;
    }
    pos++; // character after }

    // Get the next object if any
    if( retv != NULL ){
      retv->next = json_parse_object( json, &pos );
    }

  }

exit:
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}


// parses the items in an object
static json_item * json_parse_items( const char *json, int *position )
{
  json_item *retv = NULL;
  int pos = 0;
  if( ( json != NULL ) && ( position != NULL ) ){
    pos = *position;

    // scan for " while ignoring spaces, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }
    if( json[pos] != '\"' ){
      pos = -1;
      goto exit;
    }

    // found it, first create a new json_item
    retv = json_new_item();
    if( retv != NULL ){

      // now get the name
      retv->name = json_parse_string_value( json, &pos );
      if( ( pos < 0 ) || ( retv->name == NULL ) ){
        json_free_items( retv );
        retv = NULL;
        goto exit;
      }

      // scan for : while ignoring spaces, form feeds, tabs, newlines and cariage returns
      while(
        ( json[pos] != '\0' ) &&
        (
          ( json[pos] == ' '  ) ||
          ( json[pos] == '\f' ) ||
          ( json[pos] == '\t' ) ||
          ( json[pos] == '\r' ) ||
          ( json[pos] == '\n' )
        )
      ){
        pos++;
      }
      if( json[pos] != ':' ){
        json_free_items( retv );
        retv = NULL;
        pos = -1;
        goto exit;
      }
      pos++; // character after :

      // get the value
      retv->data = json_parse_value( json, &pos );
      if( pos > 0 ){

        // scan for , while ignoring spaces, form feeds, tabs, newlines and cariage returns
        while(
          ( json[pos] != '\0' ) &&
          (
            ( json[pos] == ' '  ) ||
            ( json[pos] == '\f' ) ||
            ( json[pos] == '\t' ) ||
            ( json[pos] == '\r' ) ||
            ( json[pos] == '\n' )
          )
        ){
          pos++;
        }

        // Another item?
        if( json[pos] != ',' ){
          // no, done
          retv->next = NULL;
        }
        else {
          // yes
          pos++; // skip over ,
          retv->next = json_parse_items( json, &pos ); // get the next item
        }
      }
    }
  }
exit:
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}


// parses any item's value
static json_value * json_parse_value( const char *json, int *position )
{
  json_value *retv = NULL;
  int pos = 0;
  if( ( json != NULL ) && ( position != NULL ) ){
    pos = *position;

    retv = json_new_value();
    if( retv == NULL ){
      pos = -1;
      goto exit;
    }

    // scan for any character other than spaces, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }

    // Test for the type of value
    if( json[pos] == '\"' ){
      // its a string value
      retv->type = json_string_value;
      retv->content.string = json_parse_string_value( json, &pos );
    }
    else if(
      ( json[pos] == '-' ) ||
      ( json[pos] == '+' ) ||
      ( ( json[pos] >= '0' ) && ( json[pos] <= '9' ) )
    ){
      // its a number value
      retv->type = json_number_value;
      retv->content.number = json_parse_number_value( json, &pos );
    }
    else if( json[pos] == '{' ){
      // its a(n) (list of) object(s)
      retv->type = json_object_value;
      retv->content.object = json_parse_object_value( json, &pos );
    }
    else if( json[pos] == '[' ){
      // its an array
      retv->type = json_array_value;
      retv->content.array = json_parse_array_value( json, &pos );
    }
    else if(
      ( json[pos] == 't' ) ||
      ( json[pos] == 'T' ) ||
      ( json[pos] == 'f' ) ||
      ( json[pos] == 'F' )
    ){
      // its a boolean value
      retv->type = json_boolean_value;
      retv->content.boolean = json_parse_boolean_value( json, &pos );
    }
    else if(
      ( json[pos] == 'n' ) ||
      ( json[pos] == 'N' )
    ){
      // finish testing for NULL value
      pos++;
      if( ( json[pos] != '\0' ) && ( ( json[pos] == 'u' ) || ( json[pos] == 'U' ) ) ){
        pos++;
        if( ( json[pos] != '\0' ) && ( ( json[pos] == 'l' ) || ( json[pos] == 'L' ) ) ){
          pos++;
          if( ( json[pos] != '\0' ) && ( ( json[pos] == 'l' ) || ( json[pos] == 'L' ) ) ){
            pos++; // character after NULL
          }
          else {
            pos = -1;
          }
        }
        else {
          pos = -1;
        }
      }
      else {
        pos = -1;
      }
      if( pos >= 0 ){
        // its a null value
        retv->type = json_nill_value;
        retv->content.nill = NULL;
      }
    }
    else if( json[pos] == ']' ){
      // we have reached the end of an array
      json_free_value( retv );
      retv = NULL;
    }
    else {
      // unknown data type or error
      pos = -1;
    }

    // test for error after getting the value
    if( pos < 0 ){
      json_free_value( retv );
      retv = NULL;
      goto exit;
    }

  }
exit:
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}


//  parses a 'string' item value
static json_value_string * json_parse_string_value( const char *json, int *position )
{
  json_value_string *retv = NULL;
  int pos = 0, saved;
  char prev = ' ';
  if( ( json != NULL ) && ( position != NULL ) ){
    pos = *position;

    retv = json_new_string_value();
    if( retv == NULL ){
      pos = -1;
      goto exit;
    }

    // scan for " while ignoring spaces, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }
    if( json[pos] != '\"' ){
      json_free_string_value( retv );
      retv = NULL;
      pos = -1;
      goto exit;
    }
    pos++;

    saved = pos;
    while( json[pos] != '\0' ){
      // scan for unescaped "
      if( ( json[pos] == '\"' ) && ( prev != '\\' ) ){
        break;
      }
      prev = json[pos];
      pos++;
    }
    if( json[pos] != '\"' ){
      json_free_string_value( retv );
      retv = NULL;
      pos = -1;
      goto exit;
    }
    pos++; // character after the closing "

    // Allocate the memory for the string
    retv->length = pos - saved;
    retv->value = malloc( retv->length );
    if( retv->value == NULL ){
      json_free_string_value( retv );
      retv = NULL;
      pos = -1;
      goto exit;
    }
    retv->value[retv->length - 1] = '\0';

    // copy the (still escaped) string to the value
    strncpy( retv->value, &json[saved], retv->length - 1 );

    // Unescape the string
    retv->value = str_unescape( retv->value );

    // update value length
    retv->length = strlen( retv->value ) + 1;
  }
exit:
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}



// parses a 'number' item value
static json_value_number * json_parse_number_value( const char *json, int *position )
{
  json_value_number *retv = NULL;
  int pos = 0, saved;

  if( ( json != NULL ) && ( position != NULL ) ){
    pos = *position;

    retv = json_new_number_value();
    if( retv == NULL ){
      pos = -1;
      goto exit;
    }

    // scan for any character other than spaces, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }

    // Is it a digit, + or -
    if(
      ( json[pos] == '-' ) ||
      ( json[pos] == '+' ) ||
      ( ( json[pos] >= '0' ) && ( json[pos] <= '9' ) )
    ){
      // yes, its a number value
      saved = pos;
      pos++;

      // scan for first non-digit
      while( json[pos] != '\0' ){
        if( ( json[pos] >= '0' ) && ( json[pos] <= '9' ) ) pos++;
        else break;
      }

      if( json[pos] == '\0' ){
        // this cannot possibly be the end of the data
        json_free_number_value( retv );
        retv = NULL;
        pos = -1;
        goto exit;
      }

      retv->value = strtol( &json[saved], NULL, 10 );
    }
    else {
      // its not a number value
      json_free_number_value( retv );
      retv = NULL;
      goto exit;
    }
  }
exit:
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}


// parses an 'object' item value
static json_value_object * json_parse_object_value( const char *json, int *position )
{
  json_value_object *retv = NULL;
  int pos;
  if( ( json != NULL ) && ( position != NULL ) ){
    pos = *position;
    retv = json_new_object_value();
    if( retv != NULL ){
      retv->value = json_parse_object( json, &pos );
      if( pos < 0 ){
        json_free_object_value( retv );
        retv = NULL;
        goto exit;
      }
      if( retv->value == NULL ){
        json_free_object_value( retv );
        retv = NULL;
        pos = -1;
      }
    }
  }
exit:
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}


// parses the values within an array's opening and closing brackets
static json_value_array * json_parse_array_values( const char *json, int *position )
{
  json_value_array *retv = NULL;
  int pos = 0;
  if( ( json != NULL ) && ( position != NULL ) ){
    pos = *position;

    retv = json_new_array_value();
    if( retv == NULL ){
      pos = -1;
      goto exit;
    }

    // scan for any character other than spaces, commas, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == ','  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }
    if( json[pos] == '\0' ){
      json_free_array_values( retv );
      retv = NULL;
      pos = -1;
      goto exit;
    }

    // parse the value
    retv->value = json_parse_value( json, &pos );

    if( pos > 0 ){
      // parse the next value
      if( json[pos] != ']' ){
        retv->next = json_parse_array_values( json, &pos );
      }
    }
    else {
      json_free_array_values( retv );
      retv = NULL;
      pos = -1;
      goto exit;
    }

  }
exit:
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}


// parses an 'array' item value
static json_value_array * json_parse_array_value( const char *json, int *position )
{
  json_value_array *retv = NULL;
  int pos;
  if( ( json != NULL ) && ( position != NULL ) ){
    pos = *position;

    // scan for [ while ignoring spaces, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }
    if( json[pos] != '[' ){
      pos = -1;
      goto exit;
    }
    pos++; // character after [

    // get the values
    retv = json_parse_array_values( json, &pos );
    if( ( retv == NULL ) || ( pos < 0 ) ){
      json_free_array_values( retv );
      retv = NULL;
      pos = -1;
      goto exit;
    }

    // scan for ] while ignoring spaces, form feeds, tabs, newlines and cariage returns
    while(
      ( json[pos] != '\0' ) &&
      (
        ( json[pos] == ' '  ) ||
        ( json[pos] == '\f' ) ||
        ( json[pos] == '\t' ) ||
        ( json[pos] == '\r' ) ||
        ( json[pos] == '\n' )
      )
    ){
      pos++;
    }
    if( json[pos] != ']' ){
      json_free_array_values( retv );
      retv = NULL;
      pos = -1;
      goto exit;
    }
    pos++; // character after ]

  }
exit:
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}


// parses a 'boolean' item value
static json_value_boolean * json_parse_boolean_value( const char *json, int *position )
{
  json_value_boolean *retv = NULL;
  int pos = 0;
  bool value = false;
  if( ( json != NULL ) && ( position != NULL ) ){
    pos = *position;

    if( ( json[pos] != '\0' ) && ( ( json[pos] == 't' ) || ( json[pos] == 'T' ) ) ){
      pos++;
      if( ( json[pos] != '\0' ) && ( ( json[pos] == 'r' ) || ( json[pos] == 'R' ) ) ){
        pos++;
        if( ( json[pos] != '\0' ) && ( ( json[pos] == 'u' ) || ( json[pos] == 'U' ) ) ){
          pos++;
          if( ( json[pos] != '\0' ) && ( ( json[pos] == 'e' ) || ( json[pos] == 'E' ) ) ){
            pos++; // character after TRUE
            value = true;
          }
          else {
            pos = -1;
          }
        }
        else {
          pos = -1;
        }
      }
      else {
        pos = -1;
      }
    }
    else if( ( json[pos] != '\0' ) && ( ( json[pos] == 'f' ) || ( json[pos] == 'F' ) ) ){
      pos++;
      if( ( json[pos] != '\0' ) && ( ( json[pos] == 'a' ) || ( json[pos] == 'A' ) ) ){
        pos++;
        if( ( json[pos] != '\0' ) && ( ( json[pos] == 'l' ) || ( json[pos] == 'L' ) ) ){
          pos++;
          if( ( json[pos] != '\0' ) && ( ( json[pos] == 's' ) || ( json[pos] == 'S' ) ) ){
            pos++;
            if( ( json[pos] != '\0' ) && ( ( json[pos] == 'e' ) || ( json[pos] == 'E' ) ) ){
              pos++; // character after FALSE
              value = false;
            }
            else {
              pos = -1;
            }
          }
          else {
            pos = -1;
          }
        }
        else {
          pos = -1;
        }
      }
      else {
        pos = -1;
      }
    }
    else {
      pos = -1;
    }

    if( pos >= 0 ){
      // its a boolean value
      retv = json_new_boolean_value();
      if( retv == NULL ){
        pos = -1;
      }
      else {
        retv->value = value;
      }
    }

  }
  if( position != NULL ){
    *position = pos; // update callers position
  }
  return retv;
}


static json_object * json_new_object( void )
{
  json_object * new = malloc( sizeof( json_object ) );
  if( new != NULL ){
    new->items = NULL;
    new->next = NULL;
  }
  return new;
}


static void json_free_items( json_item *item )
{
  if( item ){
    if( item->next != NULL ) json_free_items( item->next );
    if( item->name != NULL ) json_free_string_value( item->name );
    if( item->data != NULL ) json_free_value( item->data );
    free( item );
  }
}


static json_item * json_new_item( void )
{
  json_item * new = malloc( sizeof( json_item ) );
  if( new != NULL ){
    new->name = NULL;
    new->data = NULL;
    new->next = NULL;
  }
  return new;
}


static void json_free_value( json_value *value )
{
  if( value != NULL ){
    switch( value->type ){
      case json_string_value:
        json_free_string_value( value->content.string );
        break;
      case json_number_value:
        json_free_number_value( value->content.number );
        break;
      case json_object_value:
        json_free_object_value( value->content.object );
        break;
      case json_array_value:
        json_free_array_values( value->content.array );
        break;
      case json_boolean_value:
        json_free_boolean_value( value->content.boolean );
        break;
      case json_nill_value:
      default:
        break;
    }
    free( value );
  }
}


static json_value * json_new_value( void )
{
  json_value * new = malloc( sizeof( json_value ) );
  if( new != NULL ){
    new->type = json_undefined_value;
    new->content.string = NULL;
    new->content.number = NULL;
    new->content.object = NULL;
    new->content.array = NULL;
    new->content.boolean = NULL;
  }
  return new;
}


static void json_free_string_value( json_value_string *string )
{
  if( string != NULL ){
    if( string->value != NULL ) free( string->value );
    free( string );
  }
}


static json_value_string * json_new_string_value( void )
{
  json_value_string * new = malloc( sizeof( json_value_string ) );
  if( new != NULL ){
    new->value = NULL;
    new->length = 0;
  }
  return new;
}


static void json_free_number_value( json_value_number *number )
{
  if( number != NULL ){
    free( number );
  }
}


static json_value_number * json_new_number_value( void )
{
  json_value_number * new = malloc( sizeof( json_value_number ) );
  if( new != NULL ){
    new->value = 0;
  }
  return new;
}


static void json_free_object_value( json_value_object *object )
{
  if( object != NULL ){
    if( object->value != NULL ) json_free_objects( object->value );
    free( object );
  }
}


static json_value_object * json_new_object_value( void )
{
  json_value_object * new = malloc( sizeof( json_value_object ) );
  if( new != NULL ){
    new->value = NULL;
  }
  return new;
}


static void json_free_array_values( json_value_array *array )
{
  if( array != NULL ){
    if( array->next != NULL ) json_free_array_values( array->next );
    if( array->value != NULL ) json_free_value( array->value );
    free( array );
  }
}


static json_value_array * json_new_array_value( void )
{
  json_value_array * new = malloc( sizeof( json_value_array ) );
  if( new != NULL ){
    new->value = NULL;
    new->next = NULL;
  }
  return new;
}


static void json_free_boolean_value( json_value_boolean *boolean )
{
  if( boolean != NULL ){
    free( boolean );
  }
}


static json_value_boolean * json_new_boolean_value( void )
{
  json_value_boolean * new = malloc( sizeof( json_value_boolean ) );
  if( new != NULL ){
    new->value = false;
  }
  return new;
}


// Remove 1 escape level from escaped characters in str
static char *str_unescape( char * str )
{
  char *new = malloc( strlen( str ) + 1 );
  if( new ){
    int t, i;
    for( t = 0, i = 0; i <= strlen( str ); t++, i++ ){
      if( str[i] == '\\' ){
        i++;
        if( str[i] == 'b' ){
          new[t] = '\b';
        }
        else if( str[i] == 'f' ){
          new[t] = '\f';
        }
        else if( str[i] == 'n' ){
          new[t] = '\n';
        }
        else if( str[i] == 'r' ){
          new[t] = '\r';
        }
        else if( str[i] == 't' ){
          new[t] = '\t';
        }
        else {
          new[t] = str[i];
        }
      }
      else {      
        new[t] = str[i];
      }
    }
    strcpy( str, new );
    free( new );
  }
  return str;
}


/*

// Test Any valid JSON data

char *test =
"{"
"   \"Start\"      :  \"hello\"  , "
"   \"Empty\"      :  null       , "
"   \"Bool1\"      :  true       , "
"   \"Bool2\"      :  FaLsE      , "
"   \"Other\"      : {"
"                       \"var\"  : 1234, "
"                       \"nest\" : { "
"                                      \"xxx\" : \"Keep on nesting objects!\""
"                                  }"
"                    }  "
"},"
"{\"x\":[0,1,0,9,8,6,null,8],"
"\"End\"  :  \"goodbye!\" "
"}"
;


int main( int argc, char **argv )
{
  json_object *objects = json_parse_objects( test );
  if( objects ){
    json_print_objects( objects );
    json_free_objects( objects );
    puts( "Success!?" );
  }
  else {
    puts( "Returned object was empty!" );
  }
  return 0;
}

*/

