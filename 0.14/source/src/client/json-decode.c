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

/*
 *  Functions to decode the JSON formatted messages received from the
 *   server for both the broadcast and commander protocols.
 */

#include "atomic.h"

#include <stdlib.h>
#include <string.h>
#include "commander.h"
#include "broadcast.h"
#include "json.h"
#include "json-decode.h"

//
// Decodes a JSON object as returned by the broadcast protocol
// and stores the data in a new struct sia_events_list_t
//
struct sia_event_t* JSON_ParseOpenGalaxyBroadcastObject( char *object )
{
  struct sia_event_t *retv = NULL;
  json_item *i;
  json_object *o = json_parse_objects( object );
  if( o != NULL ){

    retv = malloc( sizeof( struct sia_event_t ) );
    if( retv == NULL ){
      json_free_objects( o );
      return NULL;
    }
    memset( retv, 0, sizeof( struct sia_event_t ) );

    i = o->items;
    while( i != NULL ){
      if( i->data != NULL ){

        switch( i->data->type ){

          case json_nill_value:
            break;

          case json_string_value:
            if( strcmp( i->name->value, "EventCode" ) == 0 ){
              retv->EventCode = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "EventName" ) == 0 ){
              retv->EventName = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "EventDesc" ) == 0 ){
              retv->EventDesc = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "EventAddressType" ) == 0 ){
              retv->EventAddressType = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "Date" ) == 0 ){
              retv->Date = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "Time" ) == 0 ){
              retv->Time = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "ASCII" ) == 0 ){
              retv->ASCII = strdup( i->data->content.string->value );
              retv->have_ASCII = 1;
            }
            else if( strcmp( i->name->value, "Raw" ) == 0 ){
              retv->Raw = strdup( i->data->content.string->value );
            }
            else {
              SIA_FreeEvent( retv );
              json_free_objects( o );
              return NULL;
            }
            break;

          case json_number_value:
            if( strcmp( i->name->value, "AccountID" ) == 0 ){
              retv->AccountID = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "EventAddressNumber" ) == 0 ){
              retv->EventAddressNumber = i->data->content.number->value;
              retv->have_EventAddressNumber = 1;
            }
            else if( strcmp( i->name->value, "SubscriberID" ) == 0 ){
              retv->SubscriberID = i->data->content.number->value;
              retv->have_SubscriberID = 1;
            }
            else if( strcmp( i->name->value, "AreaID" ) == 0 ){
              retv->AreaID = i->data->content.number->value;
              retv->have_AreaID = 1;
            }
            else if( strcmp( i->name->value, "PeripheralID" ) == 0 ){
              retv->PeripheralID = i->data->content.number->value;
              retv->have_PeripheralID = 1;
            }
            else if( strcmp( i->name->value, "AutomatedID" ) == 0 ){
              retv->AutomatedID = i->data->content.number->value;
              retv->have_AutomatedID = 1;
            }
            else if( strcmp( i->name->value, "TelephoneID" ) == 0 ){
              retv->TelephoneID = i->data->content.number->value;
              retv->have_TelephoneID = 1;
            }
            else if( strcmp( i->name->value, "Level" ) == 0 ){
              retv->Level = i->data->content.number->value;
              retv->have_Level = 1;
            }
            else if( strcmp( i->name->value, "Value" ) == 0 ){
              retv->Value = i->data->content.number->value;
              retv->have_Value = 1;
            }
            else if( strcmp( i->name->value, "Path" ) == 0 ){
              retv->Path = i->data->content.number->value;
              retv->have_Path = 1; 
            }
            else if( strcmp( i->name->value, "RouteGroup" ) == 0 ){
              retv->RouteGroup = i->data->content.number->value;
              retv->have_RouteGroup = 1;
            }
            else if( strcmp( i->name->value, "SubSubscriber" ) == 0 ){
              retv->SubSubscriber = i->data->content.number->value;
              retv->have_SubSubscriber = 1;
            }
            else {
              SIA_FreeEvent( retv );
              json_free_objects( o );
              return NULL;
            }
            break;

          default:
            SIA_FreeEvent( retv );
            json_free_objects( o );
            return NULL;
        }
        i = i->next;
      }
    }

    json_free_objects( o );
  }
  return retv;
}


//
// Decodes a JSON object as returned by the commander protocol
// and stores the data in a new struct commander_reply_t
//
struct commander_reply_t *JSON_ParseOpenGalaxyCommanderObject( char *object )
{
  int t;
  struct commander_reply_t *retv = NULL;
  json_item *i;
  json_value_array *a;
  json_object *o = json_parse_objects( object );
  if( o != NULL ){

    retv = malloc( sizeof( struct commander_reply_t ) );
    if( retv == NULL ){
      json_free_objects( o );
      return NULL;
    }
    memset( retv, 0, sizeof( struct commander_reply_t ) );

    i = o->items;
    while( i != NULL ){
      if( i->data != NULL ){

        switch( i->data->type ){

          case json_nill_value:
            break;

          case json_string_value:

            if( strcmp( i->name->value, "typeDesc" ) == 0 ){
              retv->typeDesc = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "command" ) == 0 ){
              retv->command = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "replyText" ) == 0 ){
              retv->text = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "helpText" ) == 0 ){
              retv->text = strdup( i->data->content.string->value );
            }
            else {
              Commander_FreeReply( retv );
              json_free_objects( o );
              return NULL;
            }
            break;

          case json_number_value:

            if( strcmp( i->name->value, "typeId" ) == 0 ){
              retv->typeId = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "success" ) == 0 ){
              retv->success = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "areaState" ) == 0 ){
              retv->areaState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "zoneNumber" ) == 0 ){
              retv->zoneNumber = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "omitState" ) == 0 ){
              retv->omitState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "zoneState" ) == 0 ){
              retv->zoneState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "panelIsOnline" ) == 0 ){
              retv->panelIsOnline = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "haveAreaState" ) == 0 ){
              retv->haveAreaState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "haveZoneState" ) == 0 ){
              retv->haveZoneState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "haveOutputState" ) == 0 ){
              retv->haveOutputState = i->data->content.number->value;
            }
            else {
              Commander_FreeReply( retv );
              json_free_objects( o );
              return NULL;
            }

            break;

          case json_array_value:

            if( strcmp( i->name->value, "areaState" ) == 0 ){
              a = i->data->content.array;
              t = 0;
              while( t < 32 ){
                if( ( a != NULL ) && ( a->value != NULL) ){
                  if( a->value->type == json_number_value ){
                    retv->areaStates[t] = a->value->content.number->value;
                    t++;
                  }
                  else {
                    break;
                  }
                  a = a->next;
                }
                else {
                  break;
                }
              }
            }
            else if( strcmp( i->name->value, "zoneState" ) == 0 ){
              a = i->data->content.array;
              t = 0;
              while( t < 65 ){
                if( ( a != NULL ) && ( a->value != NULL) ){
                  if( a->value->type == json_number_value ){
                    retv->zoneStates[t] = a->value->content.number->value;
                    t++;
                  }
                  else {
                    break;
                  }
                  a = a->next;
                }
                else {
                  break;
                }
              }
            }
            else if( strcmp( i->name->value, "outputState" ) == 0 ){
              a = i->data->content.array;
              t = 0;
              while( t < 32 ){
                if( ( a != NULL ) && ( a->value != NULL) ){
                  if( a->value->type == json_number_value ){
                    retv->outputStates[t] = a->value->content.number->value;
                    t++;
                  }
                  else {
                    break;
                  }
                  a = a->next;
                }
                else {
                  break;
                }
              }
            }
            else {
              Commander_FreeReply( retv );
              json_free_objects( o );
              return NULL;
            }
            break;

          default:
            Commander_FreeReply( retv );
            json_free_objects( o );
            return NULL;
        }
        i = i->next;
      }
    }

    json_free_objects( o );
  }
  return retv;
}



// returns 0 for success, -1 on error
// sets sref and cref to new struct or NULL
int JSON_ParseOpenGalaxyWebsocketObject(struct sia_event_t **sref, struct commander_reply_t **cref, char *object)
{
  int t;
  json_item *i, *ii;
  json_object *o, *oo;
  json_value_array *a;
  struct sia_event_t *s = NULL;
  struct commander_reply_t *c = NULL;

  if((sref == NULL) || (cref == NULL) || (object == NULL)) return -1;
  *sref = NULL;
  *cref = NULL;

  o = json_parse_objects( object );
  if( o != NULL ){

    c = malloc( sizeof( struct commander_reply_t ) );
    if( c == NULL ){
      json_free_objects( o );
      return -1;
    }
    memset( c, 0, sizeof( struct commander_reply_t ) );

    s = malloc( sizeof( struct sia_event_t ) );
    if( s == NULL ){
      json_free_objects( o );
      free( c );
      return -1;
    }
    memset( s, 0, sizeof( struct sia_event_t ) );

    i = o->items;
    while( i != NULL ){
      if( i->data != NULL ){

        switch( i->data->type ){

          case json_nill_value:
            break;

          case json_string_value:

            if( strcmp( i->name->value, "typeDesc" ) == 0 ){
              c->typeDesc = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "command" ) == 0 ){
              c->command = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "replyText" ) == 0 ){
              c->text = strdup( i->data->content.string->value );
            }
            else if( strcmp( i->name->value, "helpText" ) == 0 ){
              c->text = strdup( i->data->content.string->value );
            }
            else {
              Commander_FreeReply( c );
              SIA_FreeEvent( s );
              json_free_objects( o );
              return -1;
            }
            break;

          case json_number_value:

            if( strcmp( i->name->value, "typeId" ) == 0 ){
              c->typeId = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "success" ) == 0 ){
              c->success = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "areaState" ) == 0 ){
              c->areaState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "zoneNumber" ) == 0 ){
              c->zoneNumber = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "omitState" ) == 0 ){
              c->omitState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "zoneState" ) == 0 ){
              c->zoneState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "panelIsOnline" ) == 0 ){
              c->panelIsOnline = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "haveAreaState" ) == 0 ){
              c->haveAreaState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "haveZoneState" ) == 0 ){
              c->haveZoneState = i->data->content.number->value;
            }
            else if( strcmp( i->name->value, "haveOutputState" ) == 0 ){
              c->haveOutputState = i->data->content.number->value;
            }
            else {
              Commander_FreeReply( c );
              SIA_FreeEvent( s );
              json_free_objects( o );
              return -1;
            }

            break;

          case json_array_value:

            if( strcmp( i->name->value, "areaState" ) == 0 ){
              a = i->data->content.array;
              t = 0;
              while( t < 32 ){
                if( ( a != NULL ) && ( a->value != NULL) ){
                  if( a->value->type == json_number_value ){
                    c->areaStates[t] = a->value->content.number->value;
                    t++;
                  }
                  else {
                    break;
                  }
                  a = a->next;
                }
                else {
                  break;
                }
              }
            }
            else if( strcmp( i->name->value, "zoneState" ) == 0 ){
              a = i->data->content.array;
              t = 0;
              while( t < 65 ){
                if( ( a != NULL ) && ( a->value != NULL) ){
                  if( a->value->type == json_number_value ){
                    c->zoneStates[t] = a->value->content.number->value;
                    t++;
                  }
                  else {
                    break;
                  }
                  a = a->next;
                }
                else {
                  break;
                }
              }
            }
            else if( strcmp( i->name->value, "outputState" ) == 0 ){
              a = i->data->content.array;
              t = 0;
              while( t < 32 ){
                if( ( a != NULL ) && ( a->value != NULL) ){
                  if( a->value->type == json_number_value ){
                    c->outputStates[t] = a->value->content.number->value;
                    t++;
                  }
                  else {
                    break;
                  }
                  a = a->next;
                }
                else {
                  break;
                }
              }
            }
            else {
              Commander_FreeReply( c );
              SIA_FreeEvent( s );
              json_free_objects( o );
              return -1;
            }
            break;

          case json_object_value: // SIA message
            {
              oo = i->data->content.object->value;
              ii = oo->items;
              while( ii != NULL ){
                if( ii->data != NULL ){
                  switch( ii->data->type ){

                    case json_nill_value:
                      break;

                    case json_string_value:
                      if( strcmp( ii->name->value, "EventCode" ) == 0 ){
                        s->EventCode = strdup( ii->data->content.string->value );
                      }
                      else if( strcmp( ii->name->value, "EventName" ) == 0 ){
                        s->EventName = strdup( ii->data->content.string->value );
                      }
                      else if( strcmp( ii->name->value, "EventDesc" ) == 0 ){
                        s->EventDesc = strdup( ii->data->content.string->value );
                      }
                      else if( strcmp( ii->name->value, "EventAddressType" ) == 0 ){
                        s->EventAddressType = strdup( ii->data->content.string->value );
                      }
                      else if( strcmp( ii->name->value, "Date" ) == 0 ){
                        s->Date = strdup( ii->data->content.string->value );
                      }
                      else if( strcmp( ii->name->value, "Time" ) == 0 ){
                        s->Time = strdup( ii->data->content.string->value );
                      }
                      else if( strcmp( ii->name->value, "ASCII" ) == 0 ){
                        s->ASCII = strdup( ii->data->content.string->value );
                        s->have_ASCII = 1;
                      }
                      else if( strcmp( ii->name->value, "Raw" ) == 0 ){
                        s->Raw = strdup( ii->data->content.string->value );
                      }
                      else {
                        Commander_FreeReply( c );
                        SIA_FreeEvent( s );
                        json_free_objects( o );
                        return -1;
                      }
                      break;

                    case json_number_value:
                      if( strcmp( ii->name->value, "AccountID" ) == 0 ){
                        s->AccountID = ii->data->content.number->value;
                      }
                      else if( strcmp( ii->name->value, "EventAddressNumber" ) == 0 ){
                        s->EventAddressNumber = ii->data->content.number->value;
                        s->have_EventAddressNumber = 1;
                      }
                      else if( strcmp( ii->name->value, "SubscriberID" ) == 0 ){
                        s->SubscriberID = ii->data->content.number->value;
                        s->have_SubscriberID = 1;
                      }
                      else if( strcmp( ii->name->value, "AreaID" ) == 0 ){
                        s->AreaID = ii->data->content.number->value;
                        s->have_AreaID = 1;
                      }
                      else if( strcmp( ii->name->value, "PeripheralID" ) == 0 ){
                        s->PeripheralID = ii->data->content.number->value;
                        s->have_PeripheralID = 1;
                      }
                      else if( strcmp( ii->name->value, "AutomatedID" ) == 0 ){
                        s->AutomatedID = ii->data->content.number->value;
                        s->have_AutomatedID = 1;
                      }
                      else if( strcmp( ii->name->value, "TelephoneID" ) == 0 ){
                        s->TelephoneID = ii->data->content.number->value;
                        s->have_TelephoneID = 1;
                      }
                      else if( strcmp( ii->name->value, "Level" ) == 0 ){
                        s->Level = ii->data->content.number->value;
                        s->have_Level = 1;
                      }
                      else if( strcmp( ii->name->value, "Value" ) == 0 ){
                        s->Value = ii->data->content.number->value;
                        s->have_Value = 1;
                      }
                      else if( strcmp( ii->name->value, "Path" ) == 0 ){
                        s->Path = ii->data->content.number->value;
                        s->have_Path = 1; 
                      }
                      else if( strcmp( ii->name->value, "RouteGroup" ) == 0 ){
                        s->RouteGroup = ii->data->content.number->value;
                        s->have_RouteGroup = 1;
                      }
                      else if( strcmp( ii->name->value, "SubSubscriber" ) == 0 ){
                        s->SubSubscriber = ii->data->content.number->value;
                        s->have_SubSubscriber = 1;
                      }
                      else {
                        Commander_FreeReply( c );
                        SIA_FreeEvent( s );
                        json_free_objects( o );
                        return -1;
                      }
                      break;

                    default:
                      Commander_FreeReply( c );
                      SIA_FreeEvent( s );
                      json_free_objects( o );
                      return -1;
                  }
                  ii = ii->next;
                }
              }
              *sref = s;
            }
            break;

          default:
            Commander_FreeReply( c );
            SIA_FreeEvent( s );
            json_free_objects( o );
            return -1;
        }
        i = i->next;
      }
    }

    json_free_objects( o );
  }

  if( *sref == NULL ){
    SIA_FreeEvent( s );
  }
  *cref = c;

  return 0;
}




