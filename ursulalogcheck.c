/* -----------------------------------------------------------------------------
 * The Cyberiada Ursula game engine log analyzer
 *
 * The C library implementation
 *
 * Copyright (C) 2025 Alexey Fedoseev <aleksey@fedoseev.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/
 *
 * ----------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "ursulalogcheck.h"
#include "sha256.h"

#ifdef __DEBUG__
#include <stdio.h>
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#ifndef __SILENT__
#include <stdio.h>
#define ERROR(...) fprintf(stderr, __VA_ARGS__)
#else
#define ERROR(...)
#endif

/* -----------------------------------------------------------------------------
 * The base constants
 * ----------------------------------------------------------------------------- */

#define MAX_CONDITIONS     7
#define MAX_STR_LEN        4096
#define DELTA              0.001

/* -----------------------------------------------------------------------------
 * The base constants
 * ----------------------------------------------------------------------------- */

#define DELIMITER                         ':'
#define SO_DELIMITER                      '|'
#define COORD_START_CHAR                  '('
#define COORD_DELIMITER                   ','
#define COORD_FINISH_CHAR                 ')'
#define TIME_START_CHAR                   '['
#define TIME_FINISH_CHAR                  ']'
#define POSITION_LOG_DELIMITER            ';'
#define ATTACK_LOG_DELIMITER              ' '


#define SECRET_STRING                     "secret"
#define ID_STRING                         "id"
#define OBJ_STRING                        "obj"
#define BASE_OBJ_STRING                   "base"
#define OBJ_REQ_STRING                    "req"

#define CONDITION_TYPE_OBJECT_PROXIMITY   "proxy"
#define CONDITION_TYPE_OBJECT_APPROACHING "approach"
#define CONDITION_TYPE_OBJECT_RETIRING    "retire"
#define CONDITION_TYPE_OBJECT_MOVING      "move"
#define CONDITION_TYPE_GAME_WON           "win"
#define CONDITION_TYPE_ATTACKED           "attack"
#define CONDITION_TYPE_DAMAGED            "damage"
#define CONDITION_TYPE_DESTROYED          "destroy"
static const char* CONDITION_TYPE_STR[] = {
	CONDITION_TYPE_OBJECT_PROXIMITY,
	CONDITION_TYPE_OBJECT_APPROACHING,
	CONDITION_TYPE_OBJECT_RETIRING,
	CONDITION_TYPE_OBJECT_MOVING,
	CONDITION_TYPE_GAME_WON,
	CONDITION_TYPE_ATTACKED,
	CONDITION_TYPE_DAMAGED,
	CONDITION_TYPE_DESTROYED
};
#define CONDITION_TYPE_STR_SIZE           (sizeof(CONDITION_TYPE_STR) / sizeof(const char*))
static int find_condition(const char* s)
{
	size_t i;
	int found = -1;
	for (i = 0; i < CONDITION_TYPE_STR_SIZE; i++) {
		if (strcmp(s, CONDITION_TYPE_STR[i]) == 0) {
			found = i;
			break;
		}
	}
	return found;
}

#define OBJECT_TYPE_PLAYER                "player"
#define OBJECT_TYPE_MOB                   "mob"
#define OBJECT_TYPE_INTOBJ                "intobj"
static const char* OBJECT_TYPE_STR[] = {
	OBJECT_TYPE_PLAYER,
	OBJECT_TYPE_MOB,
	OBJECT_TYPE_INTOBJ,
	"static"
};
#define OBJECT_TYPE_STR_SIZE              (sizeof(OBJECT_TYPE_STR) / sizeof(const char*))
static int find_object_type(const char* s)
{
	size_t j;
	int found = -1;
	for (j = 0; j < OBJECT_TYPE_STR_SIZE; j++) {
		if (strcmp(s, OBJECT_TYPE_STR[j]) == 0) {
			found = j;
			break;
		}
	}
	return found;
}

#define LOG_PLAYER_START_POSITION         "Player Start Position"
#define LOG_SCENE_OBJECT_HEADER           "ID | Name | Object ID | Type | Position | HP | Damage"
#define LOG_HLINE                         "---"
#define LOG_MOB                           "mob"
#define LOG_INT_OBJECT                    "interactive_object"
#define LOG_POSITION                      "position:"
#define LOG_PLAYER                        "Player"
#define LOG_ATTACK                        "attack "
#define LOG_ATTACKED                      "attacked "
#define LOG_DIED                          "died"
#define LOG_GAME_OVER                     "Game Over: "
#define LOG_WIN                           "Win"
#define LOG_SESSION_ENDED                 "Session ended"

/* -----------------------------------------------------------------------------
 * The internal structure
 * ----------------------------------------------------------------------------- */

typedef struct {
	float x, y;
} Point;

typedef enum {
	otPlayer = 0,
	otMob,
	otIntObject,
	otStatic
} ObjectType;

typedef struct {
	ObjectType    type;                        /* object type */
	char*         class;                       /* object class name */
	unsigned char minimum;                     /* the minimum number of objects on the scene */
	unsigned char limit;                       /* the limit of objects on the scene */
	unsigned char found;                       /* objects found in the scene */
} ObjectReq;

typedef struct {
	ObjectType    type;                        /* object type */
	char*         class;                       /* object class name */
	char*         id;                          /* object id */
	Point         pos;                         /* object position (x, y) */
	Point         prev_pos;                    /* object previous position (x, y) */
	float         hp;                          /* object hp */
	float         damage;                      /* object damage */
	char          pos_predefined;              /* object position was predefined in the config file */
	char          valid;                       /* the object was checked */
} Object;

typedef enum {
	condObjectProximity,                       /* the objects are close to each other (<= argument) */
	condObjectApproaching,                     /* the primary object is approaching to the secondary object */
	condObjectRetiring,                        /* the primary object is retiring from the secondary object */
	condObjectMoving,                          /* the primary object is moving */
	condGameWon,                               /* the game was won */
	condAttacked,                              /* the primary object attacked the secondary object (= argument) */
	condDamaged,                               /* the primary object was damaged by the secondary object (=argument) */
	condDestroyed,                             /* the primary object was destroyed */
} ConditionType;

typedef struct _Condition {
	unsigned char      n;                      /* the condition number */
	ConditionType      type;                   /* the condition type */
	ObjectType         primary_obj_type;       /* the primary object */
	char*              primary_obj_class;
	ObjectType         secondary_obj_type;     /* the secondary object */
	char*              secondary_obj_class;
	float              argument;               /* the condition argument (proximity, etc.) */
	struct _Condition* second_cond;            /* the second condition (AND operand) */
} Condition;

typedef struct _UrsulaCheckerTask {
	char*                      name;           /* task identifier */
	Object*                    base_objects;   /* the base objects defined in the config */
	size_t                     base_objects_count; /* the base objects count */
	ObjectReq*                 object_reqs;    /* the object requirements */
	size_t                     object_reqs_count; /* the number of object requirements */	
	Condition*                 conditions;     /* the array of conditions */
	size_t                     conditions_count; /* the number of the tasks's conditions */
	struct _UrsulaCheckerTask* next;
} UrsulaCheckerTask;

struct _UrsulaLogCheckerData {
	char*              secret;                 /* the global secret */
	UrsulaCheckerTask* tasks;                  /* the tasks from the config file */
};

/* -----------------------------------------------------------------------------
 * Math functions
 * ----------------------------------------------------------------------------- */

#define MIN(a,b)         (((a)<(b))?(a):(b))
#define DIST(p1,p2)      (sqrt((p1.x - p2.x) * (p1.x - p2.x) + (p1.y - p2.y) * (p1.y - p2.y)))

/* -----------------------------------------------------------------------------
 * Memory utils
 * ----------------------------------------------------------------------------- */

static int copy_string(char** target, size_t* size, const char* source)
{
	char* target_str;
	size_t strsize;
	if (!source) {
		*target = NULL;
		if (size) {
			*size = 0;
		}
		return URSULA_CHECK_NO_ERROR;
	}
	strsize = strlen(source);  
	if (strsize > MAX_STR_LEN - 1) {
		strsize = MAX_STR_LEN - 1;
	}
	target_str = (char*)malloc(strsize + 1);
	strncpy(target_str, source, strsize);
	target_str[strsize] = 0;
	*target = target_str;
	if (size) {
		*size = strsize;
	}
	return URSULA_CHECK_NO_ERROR;
}

static int parse_coordinates(char* s, Point* pos)
{
	char* d;

	if(!s || !pos) {
		return URSULA_CHECK_BAD_PARAMETERS;
	}
	
	while (*s && (*s == ' ' || *s == '\t' || *s == COORD_START_CHAR)) {
		s++;
	}
	
	d = s + strlen(s) - 1;
	while (d > s && (*d == ' ' || *d == '\t' || *d == COORD_FINISH_CHAR)) {
		*d = 0;
		d--;
	}
	
	d = strchr(s, COORD_DELIMITER);
	if (!d) {
		return URSULA_CHECK_FORMAT_ERROR;
	}
	*d = 0;
	
	pos->x = atof(s);
	pos->y = atof(d + 1);
	
	return URSULA_CHECK_NO_ERROR;
}

/* -----------------------------------------------------------------------------
 * The checker config functions
 * ----------------------------------------------------------------------------- */

static UrsulaCheckerTask* cyberiada_ursula_log_new_task(const char* name)
{
	UrsulaCheckerTask* task = (UrsulaCheckerTask*)malloc(sizeof(UrsulaCheckerTask));
	if (!task) return NULL;
	memset(task, 0, sizeof(UrsulaCheckerTask));
	copy_string(&(task->name), NULL, name);
	return task;
}

static int cyberiada_ursula_log_destroy_tasks(UrsulaCheckerTask* task)
{
	size_t i;

	if (!task) {
		return URSULA_CHECK_BAD_PARAMETERS;		
	}

	for (i = 0; i < task->base_objects_count; i++) {
		Object* obj = task->base_objects + i;
		if (obj->class) free(obj->class);
		if (obj->id) free(obj->id);
	}
	if (task->base_objects) free(task->base_objects);

	for (i = 0; i < task->object_reqs_count; i++) {
		ObjectReq* objreq = task->object_reqs + i;
		if (objreq->class) free(objreq->class);
	}
	if (task->object_reqs) free(task->object_reqs);

	for (i = 0; i < task->conditions_count; i++) {
		Condition* cond = task->conditions + i;
		if (cond->primary_obj_class) free(cond->primary_obj_class);
		if (cond->secondary_obj_class) free(cond->secondary_obj_class);
		if (cond->second_cond) {
			if (cond->second_cond->primary_obj_class) free(cond->second_cond->primary_obj_class);
			if (cond->second_cond->secondary_obj_class) free(cond->second_cond->secondary_obj_class);
			free(cond->second_cond);
		}
	}
	if (task->conditions) free(task->conditions);

	if (task->name) free(task->name);

	if (task->next) {
		cyberiada_ursula_log_destroy_tasks(task->next);
	}
	
	free(task);

	return URSULA_CHECK_NO_ERROR;
}

static int cyberiada_ursula_log_task_config(const char* cfgfile, UrsulaCheckerTask** _task, const char* name)
{
	FILE* cfg;
	char* buffer = NULL;
	size_t i, line = 0;
	UrsulaCheckerTask* task = NULL;
	size_t base_objects_cnt = 0, object_reqs_cnt = 0, conditions_cnt = 0;
	int last_n = 0;

	if (!cfgfile || !*cfgfile || !_task) {
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	cfg = fopen(cfgfile, "r");
	if (!cfg) {
		ERROR("Cannot open config file %s\n", cfgfile);
		return URSULA_CHECK_BAD_PARAMETERS;		
	}

	buffer = (char*)malloc(sizeof(char) * MAX_STR_LEN);
	task = cyberiada_ursula_log_new_task(name);
	
	/* calculate the objects/objreq/condition arrays sizes */

	while(!feof(cfg)) {
		line++;
		size_t size = MAX_STR_LEN - 1;
		ssize_t strsize = getline(&buffer, &size, cfg);
		char* s = buffer;

		if (strsize > 0) {
			/*
			  Colon separated values (7 parts):
			  id(num):cond.type:pri obj type:pri obj class:sec obj type:sec ob class:arg
			  obj(base):obj type:obj class:x:y:hp:dmg
			  obj(req):obj type:obj class:minimum:limit::
			 */
			
			if (strstr(s, ID_STRING) == s ||
				strstr(s, OBJ_STRING) == s ||
				!*s || *s == ' ' || *s == '\t' || *s == '\n') {
				continue; /* skip empty lines and headers */
			}

			if (strstr(s, BASE_OBJ_STRING) == s) {
				task->base_objects_count++;
			} else if (strstr(s, OBJ_REQ_STRING) == s) {
				task->object_reqs_count++;
			} else {
				int n = atoi(s);
				if (n > last_n) {
					last_n = n;
					task->conditions_count++;
				}
			}
		}
	}

	if (!task->conditions_count) {
		ERROR("No conditions described in the config file %s!\n", cfgfile);
		free(task);
		free(buffer);
		fclose(cfg);
		return URSULA_CHECK_BAD_PARAMETERS;
	}
	if (task->conditions_count > MAX_CONDITIONS) {
		ERROR("Too many conditions (%lu) described in the config file %s!\n", task->conditions_count, cfgfile);
		free(task);
		free(buffer);
		fclose(cfg);
		return URSULA_CHECK_BAD_PARAMETERS;
	}
	
	if (task->base_objects_count) {
		task->base_objects = (Object*)malloc(sizeof(Object) * task->base_objects_count);
		memset(task->base_objects, 0, sizeof(Object) * task->base_objects_count);
	}
	if (task->object_reqs_count) {
		task->object_reqs = (ObjectReq*)malloc(sizeof(ObjectReq) * task->object_reqs_count);
		memset(task->object_reqs, 0, sizeof(sizeof(ObjectReq) * task->object_reqs_count));
	}
	task->conditions = (Condition*)malloc(sizeof(Condition) * task->conditions_count);
	memset(task->conditions, 0, sizeof(sizeof(Condition) * task->conditions_count));

	/*DEBUG("Config for task %s: o %lu or: %lu c: %lu\n",
		  name,
		  task->base_objects_count,
		  task->object_reqs_count,
		  task->conditions_count);*/

	fseek(cfg, 0, SEEK_SET);
	line = 0;
	while(!feof(cfg)) {
		size_t size = MAX_STR_LEN - 1;
		ssize_t strsize = getline(&buffer, &size, cfg);
		char* s = buffer;
		char kind = 0;
		line++;
		
		if (strsize > 0) {
			if (s[strsize - 1] == '\n') {
				s[strsize - 1] = 0;
			}

			/*
			  Colon separated values (7 parts):
			  id(num):cond.type:pri obj type:pri obj class:sec obj type:sec ob class:arg
			  obj(base):obj type:obj class:x:y:hp:dmg
			  obj(req):obj type:obj class:minimum:limit::
			 */

			if (strstr(s, ID_STRING) == s ||
				strstr(s, OBJ_STRING) == s ||
				!*s || *s == ' ' || *s == '\t' || *s == '\n') {
				continue; /* skip empty lines and headers */
			}

			for (i = 0; i < 6; i++) {
				char* d = strchr(s, DELIMITER);
				if (!d) {
					ERROR("Bad string on the line %lu in the config file %s!\n", line, cfgfile);
					goto error_csv;
				}
				*d = 0;
				/* DEBUG("line %lu, i %lu, token %s\n", line, i, s);*/
				if (i == 0) {
					if (strcmp(s, BASE_OBJ_STRING) == 0) {
						if (task->base_objects_count == 0) {
							ERROR("Bad base object line '%s' in the config file %s!\n", buffer, cfgfile);
							goto error_csv;
						}
						kind = 'b';
					} else if (strcmp(s, OBJ_REQ_STRING) == 0) {
						if (task->object_reqs_count == 0) {
							ERROR("Bad object requiremets line '%s' in the config file %s!\n", buffer, cfgfile);
							goto error_csv;
						}
						kind = 'r';
					} else {
						int n;
						kind = 'c';
						n = atoi(s);
						if (n <= 0) {
							ERROR("Bad condition number '%s' in the config file %s!\n", s, cfgfile);
							goto error_csv;
						}
						if (conditions_cnt > 0 && n == task->conditions[conditions_cnt - 1].n) {
							conditions_cnt--;
							task->conditions[conditions_cnt].second_cond = (Condition*)malloc(sizeof(Condition));
							task->conditions[conditions_cnt].second_cond->primary_obj_class = NULL;
							task->conditions[conditions_cnt].second_cond->secondary_obj_class = NULL;
							task->conditions[conditions_cnt].second_cond->n = n;
						} else {
							task->conditions[conditions_cnt].n = n;
							task->conditions[conditions_cnt].second_cond = NULL;
						}
					}
				} else if (i == 1) {
					if (kind == 'c') {
						int found = find_condition(s);
						if (found < 0) {
							ERROR("Bad condition type '%s' in the config file %s!\n", s, cfgfile);
							goto error_csv;
						}
						if (task->conditions[conditions_cnt].second_cond) {
							task->conditions[conditions_cnt].second_cond->type = (ConditionType)found;
						} else {
							task->conditions[conditions_cnt].type = (ConditionType)found;
						}
					} else if (kind == 'r') {
						int found = find_object_type(s);
						if (found < 0) {
							ERROR("Bad object type '%s' in the config file %s!\n", s, cfgfile);
							goto error_csv;
						}
						task->object_reqs[object_reqs_cnt].type = (ObjectType)found;
					} else if (kind == 'b') {
						int found = find_object_type(s);
						if (found < 0) {
							ERROR("Bad object type '%s' in the config file %s!\n", s, cfgfile);
							goto error_csv;
						}
						task->base_objects[base_objects_cnt].type = (ObjectType)found;						
					}
				} else if (i == 2) {
					if (kind == 'c' && *s) {
						int found = find_object_type(s);
						if (found < 0) {
							ERROR("Bad object type '%s' in the config file %s!\n", s, cfgfile);
							goto error_csv;
						}
						if (task->conditions[conditions_cnt].second_cond) {
							task->conditions[conditions_cnt].second_cond->primary_obj_type = (ObjectType)found;
						} else {
							task->conditions[conditions_cnt].primary_obj_type = (ObjectType)found;
						}
					} else if (kind == 'r') {
						copy_string(&(task->object_reqs[object_reqs_cnt].class), NULL, s);
					} else if (kind == 'b') {
						copy_string(&(task->base_objects[base_objects_cnt].class), NULL, s);
					}
				} else if (i == 3) {
					if (kind == 'c') {
						if (task->conditions[conditions_cnt].second_cond) {						
							copy_string(&(task->conditions[conditions_cnt].second_cond->primary_obj_class), NULL, s);
						} else {
							copy_string(&(task->conditions[conditions_cnt].primary_obj_class), NULL, s);
						}
					} else if (kind == 'r') {
						int n;
						n = atoi(s);
						if (n <= 0) {
							ERROR("Bad minimum number '%s' in the config file %s!\n", s, cfgfile);
							goto error_csv;
						}
						task->object_reqs[object_reqs_cnt].minimum = (unsigned char)n;
					} else if (kind == 'b') {
						if (*s) {
							if (parse_coordinates(s, &(task->base_objects[base_objects_cnt].pos)) != URSULA_CHECK_NO_ERROR) {
								ERROR("Bad coordinates '%s' in the config file %s!\n", s, cfgfile);
								goto error_csv;	
							}
							task->base_objects[base_objects_cnt].pos_predefined = 1;
						} else {
							task->base_objects[base_objects_cnt].pos_predefined = 0;
						}
					}
				} else if (i == 4) {
					if (kind == 'c' && *s) {
						int found = find_object_type(s);
						if (found < 0) {
							ERROR("Bad object type '%s' in the config file %s!\n", s, cfgfile);
							goto error_csv;
						}
						if (task->conditions[conditions_cnt].second_cond) {						
							task->conditions[conditions_cnt].second_cond->secondary_obj_type = (ObjectType)found;
						} else {
							task->conditions[conditions_cnt].secondary_obj_type = (ObjectType)found;
						}
					} else if (kind == 'r') {
						int n;
						n = atoi(s);
						if (n <= 0) {
							ERROR("Bad limit number '%s' in the config file %s!\n", s, cfgfile);
							goto error_csv;
						}
						task->object_reqs[object_reqs_cnt].limit = (unsigned char)n;
					} else if (kind == 'b') {
						float n;
						n = atof(s);
						task->base_objects[base_objects_cnt].hp = n;
					}
				} else if (i == 5) {
					if (kind == 'c') {
						if (task->conditions[conditions_cnt].second_cond) {
							copy_string(&(task->conditions[conditions_cnt].second_cond->secondary_obj_class), NULL, s);
						} else {
							copy_string(&(task->conditions[conditions_cnt].secondary_obj_class), NULL, s);
						}
					} else if (kind == 'r') {
						if (*s) {
							ERROR("Bad object requirement on line %lu in the config file %s!\n", line, cfgfile);
							goto error_csv;
						}
					} else if (kind == 'b') {
						float n;
						n = atof(s);
						task->base_objects[base_objects_cnt].damage = n;
					}
				}
				s = d + 1;
			}
			/*DEBUG("line %lu, i %lu, token %s\n", line, i, s);*/
			if (kind == 'c') {
				float n;
				n = atof(s);
				if (task->conditions[conditions_cnt].second_cond) {
					task->conditions[conditions_cnt].second_cond->argument = n;					
				} else {
					task->conditions[conditions_cnt].argument = n;
				}
				conditions_cnt++;
			} else if (kind == 'r') {
				object_reqs_cnt++;
			} else if (kind == 'b') {
				base_objects_cnt++;
			}
		}
		continue;

	error_csv:
		cyberiada_ursula_log_destroy_tasks(task);
		free(buffer);
		fclose(cfg);
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	if (conditions_cnt != task->conditions_count) {
		ERROR("Cannot read all conditions %lu / %lu  from the config file %s!\n",
			  conditions_cnt, task->conditions_count, cfgfile);
		cyberiada_ursula_log_destroy_tasks(task);
		free(buffer);
		fclose(cfg);		
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	if (object_reqs_cnt != task->object_reqs_count) {
		ERROR("Cannot read all object requirements %lu / %lu  from the config file %s!\n",
			  object_reqs_cnt, task->object_reqs_count, cfgfile);
		cyberiada_ursula_log_destroy_tasks(task);
		free(buffer);
		fclose(cfg);
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	if (base_objects_cnt != task->base_objects_count) {
		ERROR("Cannot read all objects %lu / %lu  from the config file %s!\n",
			  base_objects_cnt, task->base_objects_count, cfgfile);
		cyberiada_ursula_log_destroy_tasks(task);
		free(buffer);
		fclose(cfg);
		return URSULA_CHECK_BAD_PARAMETERS;
	}
	
	*_task = task;

	free(buffer);
	fclose(cfg);

	return URSULA_CHECK_NO_ERROR;
}

static int cyberiada_ursula_log_print_condition(Condition* cond, const char* tab)
{	
	if (!cond) {
		return URSULA_CHECK_BAD_PARAMETERS;		
	}

	if (tab) {
		DEBUG("%s", tab);
	}

	DEBUG("%u. ", cond->n);
	
	switch (cond->type) {
	case condObjectProximity:
		DEBUG("obj.proximity: (%s, %s)-[%.2f]-(%s, %s)\n",
			  OBJECT_TYPE_STR[cond->primary_obj_type],
			  cond->primary_obj_class,
			  cond->argument,
			  OBJECT_TYPE_STR[cond->secondary_obj_type],
			  cond->secondary_obj_class);
		break;
	case condObjectApproaching:
		DEBUG("obj.approaching: (%s, %s)->(%s, %s)\n",
			  OBJECT_TYPE_STR[cond->primary_obj_type],
			  cond->primary_obj_class,
			  OBJECT_TYPE_STR[cond->secondary_obj_type],
			  cond->secondary_obj_class);
		break;
	case condObjectRetiring:
		DEBUG("obj.retiring: (%s, %s)->(%s, %s)\n",
			  OBJECT_TYPE_STR[cond->primary_obj_type],
			  cond->primary_obj_class,
			  OBJECT_TYPE_STR[cond->secondary_obj_type],
			  cond->secondary_obj_class);		
		break;
	case condObjectMoving:
		DEBUG("obj.moving: (%s, %s)\n",
			  OBJECT_TYPE_STR[cond->primary_obj_type],
			  cond->primary_obj_class);		
		break;
	case condGameWon:
		DEBUG("game won\n");
		break;
	case condAttacked:
		DEBUG("obj.attacked: (%s, %s)-{%.2f}->(%s, %s)\n",
			  OBJECT_TYPE_STR[cond->primary_obj_type],
			  cond->primary_obj_class,
			  cond->argument,
			  OBJECT_TYPE_STR[cond->secondary_obj_type],
			  cond->secondary_obj_class);
		break;
	case condDamaged:
		DEBUG("obj.damaged: -{%.2f}->(%s, %s)\n",
			  cond->argument,
			  OBJECT_TYPE_STR[cond->primary_obj_type],
			  cond->primary_obj_class);
		break;
	case condDestroyed:
		DEBUG("obj.destroyed: (%s, %s)\n",
			  OBJECT_TYPE_STR[cond->primary_obj_type],
			  cond->primary_obj_class);
		break;
	default:
		DEBUG("Unknown contision type %d!\n", cond->type);
	}

	return URSULA_CHECK_NO_ERROR;	
}

static int print_object(Object* obj, size_t n, const char* tab)
{
	if (!obj) {
		return URSULA_CHECK_BAD_PARAMETERS;
	}
	if (obj->pos_predefined) {
		DEBUG("%s%lu. type: %s, class: %s, id: %s, pos: (%.2f, %.2f), hp: %.2f, dmg: %.2f\n",
			  tab,
			  n,
			  OBJECT_TYPE_STR[obj->type],
			  obj->class,
			  obj->id,
			  obj->pos.x,
			  obj->pos.y,
			  obj->hp,
			  obj->damage);
	} else {
		DEBUG("%s%lu. type: %s, class: %s, id: %s, pos: n/d, hp: %.2f, dmg: %.2f\n",
			  tab,
			  n,
			  OBJECT_TYPE_STR[obj->type],
			  obj->class,
			  obj->id,
			  obj->hp,
			  obj->damage);
	}
	return URSULA_CHECK_NO_ERROR;
}

static int cyberiada_ursula_log_print_task(UrsulaCheckerTask* task)
{
	size_t i;
	
	if (!task) {
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	DEBUG("\tTask %s:\n", task->name);
	if (task->base_objects) {
		DEBUG("\t\tBase objects:\n");
		for (i = 0; i < task->base_objects_count; i++) {
			Object* obj = task->base_objects + i;
			print_object(obj, i + 1, "\t\t\t");
		}
	}

	if (task->object_reqs) {
		DEBUG("\t\tObject requirements:\n");
		for (i = 0; i < task->object_reqs_count; i++) {
			ObjectReq* objreq = task->object_reqs + i;
			DEBUG("\t\t\ttype: %s, class: %s, minimum: %u, limit: %u\n",
				  OBJECT_TYPE_STR[objreq->type],
				  objreq->class,
				  objreq->minimum,
				  objreq->limit);
		}
	}

	if (task->conditions) {
		DEBUG("\t\tConditions:\n");
		for (i = 0; i < task->conditions_count; i++) {
			Condition* cond = task->conditions + i;
			cyberiada_ursula_log_print_condition(cond, "\t\t\t");
			if (cond->second_cond) {
				DEBUG("\t\t\tAND:\n");
				cyberiada_ursula_log_print_condition(cond->second_cond, "\t\t\t\t");				
			}
		}
	}

	return URSULA_CHECK_NO_ERROR;	
}

/* -----------------------------------------------------------------------------
 * The checker library functions
 * ----------------------------------------------------------------------------- */

int cyberiada_ursula_log_checker_init(UrsulaLogCheckerData** checker, const char* config_file)
{
	FILE* cfg;
	char* buffer = NULL;
	int res;
	UrsulaCheckerTask* last_task = NULL;
	
	if (!checker || !config_file) {
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	cfg = fopen(config_file, "r");
	if (!cfg) {
		ERROR("Cannot open config file %s\n", config_file);
		return URSULA_CHECK_BAD_PARAMETERS;		
	}

	buffer = (char*)malloc(sizeof(char) * MAX_STR_LEN);
	*checker = (UrsulaLogCheckerData*)malloc(sizeof(UrsulaLogCheckerData));
	memset(*checker, 0, sizeof(UrsulaLogCheckerData));
	
	while(!feof(cfg)) {
		size_t size = MAX_STR_LEN - 1;
		ssize_t strsize = getline(&buffer, &size, cfg);
		if (strsize != -1) {
			char *csvfile;
			
			if (strsize > 0 && buffer[strsize - 1] == '\n') {
				buffer[strsize - 1] = 0;
			}

			csvfile = strchr(buffer, DELIMITER);
			if (!csvfile || !*(csvfile + 1)) {
				/* skip bad lines */
				continue;
			}

			*csvfile = 0;
			csvfile++;

			if (strcmp(buffer, SECRET_STRING) == 0) {
				if ((*checker)->secret) {
					ERROR("Trying to inialize the checker secret twice!\n");
					cyberiada_ursula_log_checker_free(*checker);
					fclose(cfg);
					free(buffer);
					return URSULA_CHECK_BAD_PARAMETERS;
				}
				copy_string(&((*checker)->secret), NULL, csvfile);
			} else {
				UrsulaCheckerTask* task = NULL;
				res = cyberiada_ursula_log_task_config(csvfile, &task, buffer);
				if (res != URSULA_CHECK_NO_ERROR) {
					cyberiada_ursula_log_destroy_tasks(task);
					cyberiada_ursula_log_checker_free(*checker);
					fclose(cfg);
					free(buffer);
					return URSULA_CHECK_BAD_PARAMETERS;
				}
				
				if (!last_task) {
					(*checker)->tasks = task;
				} else {
					last_task->next = task;
				}
				last_task = task;
			}
		}
	}
	
	fclose(cfg);
	free(buffer);

	DEBUG("Checker initialized:\n");
	DEBUG("Secret: %s\n", (*checker)->secret);
	DEBUG("Tasks:\n");
	last_task = (*checker)->tasks;
	while (last_task) {
		cyberiada_ursula_log_print_task(last_task);		
		last_task = last_task->next;
	}
	DEBUG("\n");
	
	return URSULA_CHECK_NO_ERROR;
}
	
/* Free the checker internal structure */
int cyberiada_ursula_log_checker_free(UrsulaLogCheckerData* checker)
{
	if (!checker) {
		return URSULA_CHECK_BAD_PARAMETERS;		
	}

	if (checker->secret) free(checker->secret);

	if (checker->tasks) {
		cyberiada_ursula_log_destroy_tasks(checker->tasks);
	}

	free(checker);
	
	return URSULA_CHECK_NO_ERROR;
}

static char* generate_code(const char* secret, const char* task_name, int salt, UrsulaLogCheckerResult result)
{
	unsigned char hash[32];
	char* result_code = NULL;
	char buffer[MAX_STR_LEN];
	size_t i;
	int buffer_size = snprintf(buffer, MAX_STR_LEN, "%s:%s:%d:%d", secret, task_name, salt, (int)result);
	sha256_hash(hash, (unsigned char*)buffer, buffer_size);
	result_code = (char*)malloc(sizeof(char) * (32 * 2 + 1));
	for (i = 0; i < 32; i++) {
		snprintf(result_code + i * 2, 3, "%02x", hash[i]);
	}
	return result_code;
}

static int cyberiada_test_condition(unsigned int time,
									Condition* cond,
									Object* objects,
									size_t objects_count,
									Object* primary,
									size_t* primary_index,
									Object* secondary,
									float argument,
									char won)
{
	char found = 0;
	size_t i, j;
	
	if (!cond || !objects || !primary_index) {
		return 0;
	}
	
	if (cond->type == condObjectProximity) {
		for (i = 0; i < objects_count && !found; i++) {
			primary = objects + i;
			*primary_index = i;
			for (j = 0; j < objects_count && !found; j++) {
				if (i == j) continue;
				secondary = objects + j;
				if (primary->type == cond->primary_obj_type &&
					(primary->type == otPlayer ||
					 (primary->type != otPlayer && strcmp(primary->class, cond->primary_obj_class) == 0)) &&
					secondary->type == cond->secondary_obj_type &&
					(secondary->type == otPlayer ||
					 (secondary->type != otPlayer && strcmp(secondary->class, cond->secondary_obj_class) == 0))) {
					float dist = DIST(primary->pos, secondary->pos);
					/* DEBUG("Check condition proximity:\n"); */
					/* cyberiada_ursula_log_print_condition(cond, "\t"); */
					/* DEBUG("\tprimary: (%.2f, %.2f)\n", */
					/* 	  primary->pos.x, primary->pos.y); */
					/* DEBUG("\tsecondary: (%.2f, %.2f)\n", */
					/* 	  secondary->pos.x, secondary->pos.y); */
					/* DEBUG("\tdist: %.2f arg: %.2f\n", dist, cond->argument); */
					if (dist <= cond->argument) {
						found = 1;
					}
				}
			}
		}
	} else if (cond->type == condObjectMoving) {
		for (i = 0; i < objects_count && !found; i++) {
			primary = objects + i;
			*primary_index = i;
			if (primary->type == cond->primary_obj_type &&
				(primary->type == otPlayer ||
				 (primary->type != otPlayer && strcmp(primary->class, cond->primary_obj_class))) &&
				DIST(primary->pos, primary->prev_pos) > 0) {
				found = 1;
			}
		}
	} else if (cond->type == condObjectApproaching) {
		for (i = 0; i < objects_count && !found; i++) {
			primary = objects + i;
			*primary_index = i;
			for (j = 0; j < objects_count && !found; j++) {
				if (i == j) continue;
				secondary = objects + j;
				if (primary->type == cond->primary_obj_type &&
					(primary->type == otPlayer ||
					 (primary->type != otPlayer && strcmp(primary->class, cond->primary_obj_class) == 0)) &&
					secondary->type == cond->secondary_obj_type &&
					(secondary->type == otPlayer ||
					 (secondary->type != otPlayer && strcmp(secondary->class, cond->secondary_obj_class) == 0))) {
					float dist = DIST(primary->pos, secondary->pos);
					float prev_dist = DIST(primary->prev_pos, secondary->prev_pos);
					/* DEBUG("Check condition approaching:\n"); */
					/* cyberiada_ursula_log_print_condition(cond, "\t"); */
					/* DEBUG("\tprimary: (%.2f, %.2f) prev (%.2f, %.2f)\n", */
					/* 	  primary->pos.x, primary->pos.y, primary->prev_pos.x, primary->prev_pos.y); */
					/* DEBUG("\tsecondary: (%.2f, %.2f) prev (%.2f, %.2f)\n", */
					/* 	  secondary->pos.x, secondary->pos.y, secondary->prev_pos.x, secondary->prev_pos.y); */
					/* DEBUG("\tdist: %.2f prev dist: %.2f\n", dist, prev_dist); */
					if (dist < prev_dist) {
						found = 1;
					}
				}
			}
		}	
	} else if (cond->type == condObjectRetiring) {
		for (i = 0; i < objects_count && !found; i++) {
			primary = objects + i;
			*primary_index = i;
			for (j = 0; j < objects_count && !found; j++) {
				if (i == j) continue;
				secondary = objects + j;
				if (primary->type == cond->primary_obj_type &&
					(primary->type == otPlayer ||
					 (primary->type != otPlayer && strcmp(primary->class, cond->primary_obj_class) == 0)) &&
					secondary->type ==cond->secondary_obj_type &&
					(secondary->type == otPlayer ||
					 (secondary->type != otPlayer && strcmp(secondary->class, cond->secondary_obj_class) == 0)) &&
					DIST(primary->pos, secondary->pos) > DIST(primary->prev_pos, secondary->prev_pos)) {
					found = 1;
				}
			}
		}		
	} else if (cond->type == condAttacked) {
		if (!primary || !secondary) {
			return 0;
		}
		if (primary->type == cond->primary_obj_type &&
			(primary->type == otPlayer ||
			 (primary->type != otPlayer && strcmp(primary->class, cond->primary_obj_class) == 0)) &&
			secondary->type == cond->secondary_obj_type &&
			(secondary->type == otPlayer ||
			 (secondary->type != otPlayer && strcmp(secondary->class, cond->secondary_obj_class) == 0)) &&
			cond->argument >= argument) {
			found = 1;
		}
	} else if (cond->type == condDamaged) {
		if (!primary) {
			return 0;
		}
		if (primary->type == cond->primary_obj_type &&
			(primary->type == otPlayer ||
			 (primary->type != otPlayer && strcmp(primary->class, cond->primary_obj_class))) &&
			cond->argument >= argument) {
			found = 1;
		}
	} else if (cond->type == condDestroyed) {
		if (!primary) {
			return 0;
		}
		if (primary->type == cond->primary_obj_type &&
			(primary->type == otPlayer ||
			 (primary->type != otPlayer && strcmp(primary->class, cond->primary_obj_class)))) {
			found = 1;
		}
	} else if (cond->type == condGameWon) {
		found = won;
	}

	if (found) {
		DEBUG("Condition found on time %u: ", time);
		cyberiada_ursula_log_print_condition(cond, "");
		if (cond->second_cond) {
			return cyberiada_test_condition(time, cond->second_cond, objects, objects_count, NULL, primary_index, NULL, 0, 0);
		}
		return 1;
	}
	return 0;
}

static int cyberiada_test_all_conditions(unsigned int time,
										 UrsulaCheckerTask* task,
										 Object* objects,
										 size_t objects_count,
										 unsigned char** cond_matrix,
										 Object* primary,
										 size_t primary_index,
										 Object* secondary,
										 float argument,
										 char won)
{
	size_t i, j;
	for (i = 0; i < task->conditions_count; i++) {
		Condition* cond = task->conditions + i;
		if (cyberiada_test_condition(time, cond, objects, objects_count,
									 primary, &primary_index, secondary, argument, won)) {
			if (cond->type == condGameWon) {
				size_t obj_index;
				for (obj_index = 0; obj_index < objects_count; obj_index++) {
					char found = 0;
					size_t j;
					for (j = i + 1; j < task->conditions_count; j++) {
						if (cond_matrix[j][obj_index]) {
							found = 1;
							break;
						}
					}
					if (!found) {
						cond_matrix[i][obj_index] = 1;
					}
				}
			} else {
				char found = 0;
				for (j = i + 1; j < task->conditions_count; j++) {
					if (cond_matrix[j][primary_index]) {
						found = 1;
						break;
					}
				}
				if (!found) {
					cond_matrix[i][primary_index] = 1;
				}
			}
		}
	}
	return 0;
}							   
							   
/* Check the CyberiadaML program from the buffer in the context of the task */
int cyberiada_ursula_log_checker_check_log(UrsulaLogCheckerData* checker,
										   const char* task_name,
										   int salt,
										   const char* log_file,
										   UrsulaLogCheckerResult* result,
										   char** result_code)
{
	UrsulaLogCheckerResult res = URSULA_CHECK_RESULT_ERROR;
	UrsulaCheckerTask*     task;
	Object*                objects = NULL;             /* the actual objects */
	size_t                 objects_count = 0;          /* the actual objects count */
	unsigned char**        cond_matrix = NULL;         /* the matrix of satisfied conditions (objects x conditions) */
	size_t i, line = 0;
	char* buffer = NULL;
	FILE* log = NULL;
	char state = 'p';
	Point player_pos = {0.0, 0.0};

	if (!checker || !task_name || !log_file) {
		ERROR("Bad check program arguments!\n");
		if (result) {
			*result = URSULA_CHECK_RESULT_ERROR;
		}
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	task = checker->tasks;
	while (task) {
		if (strcmp(task->name, task_name) == 0) {
			/* found! */
			break;
		}
		task = task->next;
	}
	if (!task) {
		ERROR("Cannot find task with name %s\n", task_name);
		if (result) {
			*result = URSULA_CHECK_RESULT_ERROR;
		}
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	log = fopen(log_file, "r");
	if (!log) {
		ERROR("Cannot open log file %s\n", log_file);
		if (result) {
			*result = URSULA_CHECK_RESULT_ERROR;
		}
		return URSULA_CHECK_BAD_PARAMETERS;		
	}
		
	buffer = (char*)malloc(sizeof(char) * MAX_STR_LEN);

	while(!feof(log)) {
		line++;
		size_t size = MAX_STR_LEN - 1;
		ssize_t strsize = getline(&buffer, &size, log);
		if (strsize <= 0) {
			continue;
		}

		if (buffer[strsize - 1] == '\n') {
			buffer[strsize - 1] = 0;
		}

		if (state == 'p') {
			if (strstr(buffer, LOG_PLAYER_START_POSITION) == buffer) {
				char* s = buffer + strlen(LOG_PLAYER_START_POSITION);
				if (parse_coordinates(s, &player_pos) != URSULA_CHECK_NO_ERROR) {
					ERROR("Bad players coordinates %s in the log file %s.\n", s, log_file);
					goto error_log;
				}
				state = 's';
			}
		} else if (state == 's') {
			if (strstr(buffer, LOG_SCENE_OBJECT_HEADER) == buffer) {
				state = 'o';
			}
		} else if (state == 'o') {
			if (!objects) {
				objects_count++;
				if (strstr(buffer, LOG_HLINE) == buffer) {
					state = 's';
					if (objects_count == 0) {
						fclose(log);
						free(buffer);
						ERROR("No objects in log\n");
						if (result) {
							*result = URSULA_CHECK_RESULT_ERROR;
						}
						return URSULA_CHECK_BAD_PARAMETERS;		
					}
					/* add player object */
					objects = (Object*)malloc(sizeof(Object) * objects_count); /* reserve for players */
					memset(objects, 0, sizeof(Object) * objects_count);
					i = 0;
					line = 0;
					fseek(log, 0, SEEK_SET); /* looking from the beginning */
				}
			} else {
				if (strstr(buffer, LOG_HLINE) == buffer) {
					int found = -1;
					
					if (i != objects_count - 1) {
						ERROR("Wrong number of objects %lu instead of %lu in the log file %s.\n",
							  i, objects_count - 1, log_file);
						goto error_log;
					}
					/* add player */
					objects[i].type = otPlayer;
					objects[i].class = NULL;
					objects[i].id = NULL;
					objects[i].pos.x = objects[i].prev_pos.x = player_pos.x;
					objects[i].pos.y = objects[i].prev_pos.x = player_pos.y;
					objects[i].hp = 0.0;
					objects[i].damage = 0.0;
					objects[i].pos_predefined = 1;

					DEBUG("Log objects:\n");
					for (i = 0; i < objects_count; i++) {
						print_object(objects + i, i + 1, "\t");
					}
					
					/* check objects */

					for (i = 0; i < objects_count; i++) {
						size_t j;
						for (j = 0; j < task->base_objects_count; j++) {
							char types = task->base_objects[j].type == objects[i].type,
								classes = ((objects[i].class && *(objects[i].class) &&
											task->base_objects[j].class && *(task->base_objects[j].class) &&
											strcmp(task->base_objects[j].class, objects[i].class) == 0) ||
										   !task->base_objects[j].class || !*(task->base_objects[j].class)),
								positions = ((task->base_objects[j].pos_predefined &&
											  DIST(objects[i].pos, task->base_objects[j].pos) <= DELTA) ||
											 !task->base_objects[j].pos_predefined),
								hps = ((task->base_objects[j].hp > 0 &&
										task->base_objects[j].hp == objects[i].hp) ||
									   task->base_objects[j].hp == 0),
								damages = (((task->base_objects[j].damage > 0 &&
											 task->base_objects[j].damage == objects[i].damage) ||
											task->base_objects[j].damage == 0));
							
							/*DEBUG("compare i %lu and j %lu types: %d classes: %d pos: %d hps: %d dmg: %d valid: %d\n",
							  i, j, types, classes, positions, hps, damages, task->base_objects[j].valid);*/
							if (types && classes && positions && hps && damages && !task->base_objects[j].valid) {
								task->base_objects[j].valid = 1;
							}
						}
						for (j = 0; j < task->object_reqs_count; j++) {
							if (task->object_reqs[j].type == objects[i].type &&
								strcmp(task->object_reqs[j].class, objects[i].class) == 0) {

								task->object_reqs[j].found++;
							}
						}
					}

					found = -1;
					for (i = 0; i < task->base_objects_count; i++) {
						if (!task->base_objects[i].valid) {
							found = i;
							break;
						}
					}
					if (found >= 0) {
						ERROR("Log does not contain correct base object type %s class %s\n",
							  OBJECT_TYPE_STR[task->base_objects[found].type],
							  task->base_objects[found].class);
						goto error_log;
					}
					
					for (i = 0; i < task->object_reqs_count; i++) {
						if (task->object_reqs[i].found < task->object_reqs[i].minimum ||
							task->object_reqs[i].found > task->object_reqs[i].limit) {
							found = i;
							break;
						}
					}
					if (found >= 0) {
						ERROR("Log does not contain object corresponding the obj. req. type %s class %s\n",
							  OBJECT_TYPE_STR[task->object_reqs[found].type],
							  task->object_reqs[found].class);
						goto error_log;
					}

					cond_matrix = (unsigned char**)malloc(sizeof(unsigned char*) * MAX_CONDITIONS);
					for (i = 0; i < MAX_CONDITIONS; i++) {
						cond_matrix[i] = (unsigned char*)malloc(sizeof(unsigned char) * objects_count);
						memset(cond_matrix[i], 0, sizeof(unsigned char) * objects_count);
					}
					
					state = 'l';
				} else {				
					/* parse objects */
					/* 0    1      2           3      4          5    6      */
					/* ID | Name | Object ID | Type | Position | HP | Damage */
					int j;
					char* s = buffer;
					float n = 0.0;
					for (j = 0; j < 6; j++) {
						char* d = strchr(s, SO_DELIMITER), *d2;
						if (!d) {
							ERROR("Bad string '%s' on the line %lu in the log file %s!\n", s, line, log_file);
							goto error_log;
						}
						*d = 0;
						while (s < d && (*s == ' ' || *s == '\t')) {
							s++;
						}
						d2 = d - 1;
						while (d2 > s && (*d2 == ' ' || *d2 == '\t')) {
							*d2 = 0;
							d2--;
						}
						/* DEBUG("token line-%lu j-%d '%s'\n", line, j, s); */
						if (j == 0) {
							if (*s) {
								copy_string(&(objects[i].id), NULL, s);
							} else {
								ERROR("Bad object id '%s' on the line %lu in the log file %s!\n", s, line - 1, log_file);
								goto error_log;
							}
						} else if (j == 1) {
							if (*s) {
								copy_string(&(objects[i].class), NULL, s);
							} else {
								ERROR("Bad object class '%s' on the line %lu in the log file %s!\n", s, line - 1, log_file);
								goto error_log;
							}
						} else if (j == 2) {
							/* skip node id */
						} else if (j == 3) {
							if (strcmp(s, LOG_MOB) == 0) {
								objects[i].type = otMob;
							} else if (strcmp(s, LOG_INT_OBJECT) == 0) {
								objects[i].type = otIntObject;
							} else {
								objects[i].type = otStatic;
							}							
						} else if (j == 4) {
							if (parse_coordinates(s, &(objects[i].pos)) != URSULA_CHECK_NO_ERROR) {
								ERROR("Bad players coordinates %s in the log file %s.\n", s, log_file);
								goto error_log;
							}
							objects[i].prev_pos.x = objects[i].pos.x;
							objects[i].prev_pos.y = objects[i].pos.y;;
							objects[i].pos_predefined = 1;
						} else if (j == 5) {
							n = atof(s);
							objects[i].hp = n;
						}
						s = d + 1;
					}
					
					n = atof(s);
					objects[i].damage = n;

					i++;
				}
			}
		} else if (state == 'l') {
			char* s = buffer, *d;
			unsigned int time = 0;
			if (*s != TIME_START_CHAR) {
				continue;
			}
			s++;
			d = strchr(s, TIME_FINISH_CHAR);
			if (!d) {
				ERROR("Bad log string '%s' format (no time section) in the log file %s.\n", s, log_file);
				goto error_log;
			}
			*d = 0;
			time = atoi(s);
			s = d + 1;
			while(*s && (*s == ' ' || *s == '\t')) s++;
			if (strstr(s, LOG_POSITION) != NULL) {
				while(*s) {
					Object* pos_object = NULL;
					char *d, *d2;
					char player_pos = 0;
					
					while(*s && (*s == ' '  || *s == '\t')) s++;
					d = strchr(s, POSITION_LOG_DELIMITER);
					if (!d) {
						d = s + strlen(s);
					} else {
						*d = 0;
					}

					d2 = strchr(s, ATTACK_LOG_DELIMITER);
					if (!d2) {
						ERROR("Bad position string '%s' on time %u in the log file %s.\n", s, time, log_file);
						goto error_log;
					}
					*d2 = 0;

					if (strstr(s, LOG_PLAYER) == s) {
						player_pos = 1;
						for (i = 0; i < objects_count; i++) {
							if (objects[i].type == otPlayer) {
								pos_object = objects + i; 
								break;
							}
						}
					} else {
						for (i = 0; i < objects_count; i++) {
							if (objects[i].type != otPlayer && strcmp(s, objects[i].id) == 0) {
								pos_object = objects + i;
								break;
							}
						}
					}
					if (!pos_object) {
						ERROR("Unknown object %s in position string on time %u in the log file %s.\n", s, time, log_file);
						goto error_log;
					}
					s = d2 + 1;

					pos_object->prev_pos.x = pos_object->pos.x;
					pos_object->prev_pos.y = pos_object->pos.y;

					if (!player_pos) {
						/* skip "position:" */
						d2 = strchr(s, ATTACK_LOG_DELIMITER);
						if (!d2) {
							ERROR("Bad position string '%s' on time %u in the log file %s.\n", s, time, log_file);
							goto error_log;
						}
						s = d2 + 1;
					}
						
					if (parse_coordinates(s, &(pos_object->pos)) != URSULA_CHECK_NO_ERROR) {
						ERROR("Bad coordinates %s in position string on time %u in the log file %s.\n", s, time, log_file);
						goto error_log;
					}
					
					s = d + 1;
				}

				cyberiada_test_all_conditions(time, task, objects, objects_count, cond_matrix, NULL, 0, NULL, 0.0, 0);
				
			} else if (strstr(s, LOG_ATTACK) == s) {
				size_t attacker_index = 0;
				Object *attacker = NULL, *target = NULL;
				float damage = 0; 

				s += strlen(LOG_ATTACK);
				for (i = 0; i < 5; i++) {
					d = strchr(s, ATTACK_LOG_DELIMITER);
					if (!d) {
						ERROR("Bad attack string on time %u in the log file %s.\n", time, log_file);
						goto error_log;
					}
					*d = 0;
					/* DEBUG("token time %u i %lu '%s'\n", time, i, s); */
					if (i == 0) {
						size_t j;
						for (j = 0; j < objects_count; j++) {
							if ((objects[j].type == otPlayer && strcmp(LOG_PLAYER, s) == 0) ||
								(objects[j].type != otPlayer && strcmp(objects[j].id, s) == 0)) {
								attacker_index = j;
								attacker = objects + j;
							}
						}
						if (!attacker) {
							ERROR("Bad attacker id '%s' on time %u in the log file %s.\n", s, time, log_file);
							goto error_log;
						}
					} else if (i == 2) {
						damage = atof(s);
					}
					s = d + 1;
				}
				for (i= 0; i < objects_count; i++) {
					if ((objects[i].type == otPlayer && strcmp(LOG_PLAYER, s) == 0) ||
						(objects[i].type != otPlayer && strcmp(objects[i].id, s) == 0)) {
						target = objects + i;
					}
				}
				if (!target) {
					ERROR("Bad target id %s on time %u in the log file %s.\n", s, time, log_file);
					goto error_log;
				}
				
				cyberiada_test_all_conditions(time, task, objects, objects_count, cond_matrix,
											  attacker, attacker_index, target, damage, 0);

			} else if (strstr(s, LOG_ATTACKED) == s) {
				s += strlen(LOG_ATTACKED);
				char* d2;
				size_t target_index = 0;
				Object *target = NULL;
				float damage = 0; 
				for (i = 0; i < 4; i++) {
					d = strchr(s, ATTACK_LOG_DELIMITER);
					if (!d) {
						ERROR("Bad attacked string on time %u in the log file %s.\n", time, log_file);
						goto error_log;
					}
					*d = 0;
					d2 = d - 1;
					if (*d2 == ',') *d2 = 0;
					/* DEBUG("token time %u i %lu '%s'\n", time, i, s); */
					if (i == 0) {
						size_t j;
						for (j = 0; j < objects_count; j++) {
							if ((objects[j].type == otPlayer && strcmp(LOG_PLAYER, s) == 0) ||
								(objects[j].type != otPlayer && strcmp(objects[j].id, s) == 0)) {
								target_index = j;
								target = objects + j;
							}
						}
						if (!target) {
							ERROR("Bad target id '%s' on time %u in the log file %s.\n", s, time, log_file);
							goto error_log;
						}
					} else if (i == 3) {
						damage = atof(s);
					}
					s = d + 1;
				}
				
				cyberiada_test_all_conditions(time, task, objects, objects_count, cond_matrix,
											  target, target_index, NULL, damage, 0);

			} else if (strstr(s, LOG_DIED) != NULL) {
				Object* died = NULL;
				size_t died_index = 0;
				d = strchr(s, ATTACK_LOG_DELIMITER);
				if (!d) {
					ERROR("Bad died string on time %u in the log file %s.\n", time, log_file);
					goto error_log;
				}
				*d = 0;
				for (i= 0; i < objects_count; i++) {
					if ((objects[i].type == otPlayer && strcmp(LOG_PLAYER, s) == 0) ||
						(objects[i].type != otPlayer && strcmp(objects[i].id, s) == 0)) {
						died = objects + i;
						died_index = i;
					}
				}
				if (!died) {
					ERROR("Bad died id %s on time %u in the log file %s.\n", s, time, log_file);
					goto error_log;
				}

				cyberiada_test_all_conditions(time, task, objects, objects_count, cond_matrix,
											  died, died_index, NULL, 0.0, 0);

			} else if (strstr(s, LOG_GAME_OVER) == s) {
				s += strlen(LOG_GAME_OVER);
				if (strcmp(s, LOG_WIN) != 0) {
					continue;
				}

				cyberiada_test_all_conditions(time, task, objects, objects_count, cond_matrix,
											  NULL, 0, NULL, 0.0, 1);
				
			} else if (strstr(s, LOG_SESSION_ENDED) == s) {
				break;
			} else {
				ERROR("Bad log string on time %u format in the log file %s.\n", time, log_file);
				goto error_log;				
			}
		} else {
			ERROR("Unknown state '%c', line %lu while reading log %s\n", state, line, log_file);
			goto error_log;
		}
	}

	res = 0;
	if (cond_matrix) {
		size_t j;
		DEBUG("Condition matrix:\n\t  ");
		for (j = 0; j < objects_count; j++) {
			if (objects[j].type == otPlayer) {
				DEBUG(" PL ");
			} else {
				DEBUG("%3s ", objects[j].id);
			} 
		}
		DEBUG("\n");
		for (i = 0; i < task->conditions_count; i++) {
			char cond_bit = 0;
			DEBUG("\t%lu ", i);
			for (j = 0; j < objects_count; j++) {
				DEBUG(" %d  ", cond_matrix[i][j]);
				if (!cond_bit && cond_matrix[i][j]) {
					cond_bit = 1;
				}
			}
			DEBUG("\n");
			res |= (cond_bit << i);
		}
	}
	
	if (objects) {
		for (i = 0; i < objects_count; i++) {
			Object* obj = objects + i;
			if (obj->class) free(obj->class);
			if (obj->id) free(obj->id);
		}
		free(objects);
	}

	if (cond_matrix) {
		for (i = 0; i < MAX_CONDITIONS; i++) {
			if (cond_matrix[i]) free(cond_matrix[i]);
		}
		free(cond_matrix);
	}
	
	free(buffer);
	fclose(log);
	
	if (result) {
		*result = res;
	}
	
	if (result_code) {
		*result_code = generate_code(checker->secret, task_name, salt, res);
	}
	
	return URSULA_CHECK_NO_ERROR;

error_log:
	
	fclose(log);
	free(buffer);
	if (objects) {
		for (i = 0; i < objects_count; i++) {
			Object* obj = objects + i;
			if (obj->class) free(obj->class);
			if (obj->id) free(obj->id);
		}
		free(objects);
	}
	if (cond_matrix) {
		for (i = 0; i < MAX_CONDITIONS; i++) {
			if (cond_matrix[i]) free(cond_matrix[i]);
		}
		free(cond_matrix);
	}
	if (result) {
		*result = URSULA_CHECK_RESULT_ERROR;
	}
	return URSULA_CHECK_BAD_PARAMETERS;	
}
