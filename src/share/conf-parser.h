/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <syslog.h>

#include "alloc-util.h"
#include "log.h"
#include "macro.h"

/* An abstract parser for simple, line based, shallow configuration
 * files consisting of variable assignments only. */

/* Argument list for parsers of specific configuration settings. */
#define CONFIG_PARSER_ARGUMENTS                 \
        const char *unit,                       \
        const char *filename,                   \
        unsigned line,                          \
        const char *section,                    \
        unsigned section_line,                  \
        const char *lvalue,                     \
        int ltype,                              \
        const char *rvalue,                     \
        void *data,                             \
        void *userdata

/* Prototype for a parser for a specific configuration setting */
typedef int (*ConfigParserCallback)(CONFIG_PARSER_ARGUMENTS);

/* A macro declaring a function prototype, following the typedef above, simply because it's so cumbersomely long
 * otherwise. (And current emacs gets irritatingly slow when editing files that contain lots of very long function
 * prototypes on the same screen…) */
#define CONFIG_PARSER_PROTOTYPE(name) int name(CONFIG_PARSER_ARGUMENTS)

/* Prototype for a parser for a specific configuration setting */
typedef int (*ConfigParserCallback)(const char *unit,
                                    const char *filename,
                                    unsigned line,
                                    const char *section,
                                    unsigned section_line,
                                    const char *lvalue,
                                    int ltype,
                                    const char *rvalue,
                                    void *data,
                                    void *userdata);

/* Wraps information for parsing a specific configuration variable, to
 * be stored in a simple array */
typedef struct ConfigTableItem {
        const char *section;            /* Section */
        const char *lvalue;             /* Name of the variable */
        ConfigParserCallback parse;     /* Function that is called to parse the variable's value */
        int ltype;                      /* Distinguish different variables passed to the same callback */
        void *data;                     /* Where to store the variable's data */
} ConfigTableItem;

/* Wraps information for parsing a specific configuration variable, to
 * be stored in a gperf perfect hashtable */
typedef struct ConfigPerfItem {
        const char *section_and_lvalue; /* Section + "." + name of the variable */
        ConfigParserCallback parse;     /* Function that is called to parse the variable's value */
        int ltype;                      /* Distinguish different variables passed to the same callback */
        size_t offset;                  /* Offset where to store data, from the beginning of userdata */
} ConfigPerfItem;

/* Prototype for a low-level gperf lookup function */
typedef const ConfigPerfItem* (*ConfigPerfItemLookup)(const char *section_and_lvalue, unsigned length);

/* Prototype for a generic high-level lookup function */
typedef int (*ConfigItemLookup)(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *func,
                int *ltype,
                void **data,
                void *userdata);

/* Linear table search implementation of ConfigItemLookup, based on
 * ConfigTableItem arrays */
int config_item_table_lookup(const void *table, const char *section, const char *lvalue, ConfigParserCallback *func, int *ltype, void **data, void *userdata);

/* gperf implementation of ConfigItemLookup, based on gperf
 * ConfigPerfItem tables */
int config_item_perf_lookup(const void *table, const char *section, const char *lvalue, ConfigParserCallback *func, int *ltype, void **data, void *userdata);

int config_parse(const char *unit,
                 const char *filename,
                 FILE *f,
                 const char *sections,  /* nulstr */
                 ConfigItemLookup lookup,
                 const void *table,
                 bool relaxed,
                 bool allow_include,
                 bool warn,
                 void *userdata);

int config_parse_many(const char *conf_file,      /* possibly NULL */
                      const char *conf_file_dirs, /* nulstr */
                      const char *sections,       /* nulstr */
                      ConfigItemLookup lookup,
                      const void *table,
                      bool relaxed,
                      void *userdata);

#define DEFINE_CONFIG_PARSE_ENUM(function,name,type,msg)                \
        int function(const char *unit,                                  \
                     const char *filename,                              \
                     unsigned line,                                     \
                     const char *section,                               \
                     unsigned section_line,                             \
                     const char *lvalue,                                \
                     int ltype,                                         \
                     const char *rvalue,                                \
                     void *data,                                        \
                     void *userdata) {                                  \
                                                                        \
                type *i = data, x;                                      \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                if ((x = name##_from_string(rvalue)) < 0) {             \
                        log_syntax(unit, LOG_ERR, filename, line, -x,   \
                                   msg ", ignoring: %s", rvalue);       \
                        return 0;                                       \
                }                                                       \
                                                                        \
                *i = x;                                                 \
                return 0;                                               \
        }

#define DEFINE_CONFIG_PARSE_ENUMV(function,name,type,invalid,msg)              \
        int function(const char *unit,                                         \
                     const char *filename,                                     \
                     unsigned line,                                            \
                     const char *section,                                      \
                     unsigned section_line,                                    \
                     const char *lvalue,                                       \
                     int ltype,                                                \
                     const char *rvalue,                                       \
                     void *data,                                               \
                     void *userdata) {                                         \
                                                                               \
                type **enums = data, x, *ys;                                   \
                _cleanup_free_ type *xs = NULL;                                \
                const char *word, *state;                                      \
                size_t l, i = 0;                                               \
                                                                               \
                assert(filename);                                              \
                assert(lvalue);                                                \
                assert(rvalue);                                                \
                assert(data);                                                  \
                                                                               \
                xs = new0(type, 1);                                            \
                if (!xs)                                                       \
                        return -ENOMEM;                                        \
                                                                               \
                *xs = invalid;                                                 \
                                                                               \
                FOREACH_WORD(word, l, rvalue, state) {                         \
                        _cleanup_free_ char *en = NULL;                        \
                        type *new_xs;                                          \
                                                                               \
                        en = strndup(word, l);                                 \
                        if (!en)                                               \
                                return -ENOMEM;                                \
                                                                               \
                        if ((x = name##_from_string(en)) < 0) {                \
                                log_syntax(unit, LOG_ERR, filename, line,      \
                                       -x, msg ", ignoring: %s", en);          \
                                continue;                                      \
                        }                                                      \
                                                                               \
                        for (ys = xs; x != invalid && *ys != invalid; ys++) {  \
                                if (*ys == x) {                                \
                                        log_syntax(unit, LOG_ERR, filename,    \
                                              line, -x,                        \
                                              "Duplicate entry, ignoring: %s", \
                                              en);                             \
                                        x = invalid;                           \
                                }                                              \
                        }                                                      \
                                                                               \
                        if (x == invalid)                                      \
                                continue;                                      \
                                                                               \
                        *(xs + i) = x;                                         \
                        new_xs = realloc(xs, (++i + 1) * sizeof(type));        \
                        if (new_xs)                                            \
                                xs = new_xs;                                   \
                        else                                                   \
                                return -ENOMEM;                                \
                                                                               \
                        *(xs + i) = invalid;                                   \
                }                                                              \
                                                                               \
                free(*enums);                                                  \
                *enums = xs;                                                   \
                xs = NULL;                                                     \
                                                                               \
                return 0;                                                      \
        }

#define DEFINE_CONFIG_PARSE(function, parser, msg)                      \
        CONFIG_PARSER_PROTOTYPE(function) {                             \
                int *i = data, r;                                       \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                r = parser(rvalue);                                     \
                if (r < 0) {                                            \
                        log_syntax(unit, LOG_WARNING, filename, line, r, \
                                   msg ", ignoring: %s", rvalue);       \
                        return 0;                                       \
                }                                                       \
                                                                        \
                *i = r;                                                 \
                return 0;                                               \
        }

#define DEFINE_CONFIG_PARSE_PTR(function, parser, type, msg)            \
        CONFIG_PARSER_PROTOTYPE(function) {                             \
                type *i = ASSERT_PTR(data);                             \
                int r;                                                  \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                                                                        \
                r = parser(rvalue, i);                                  \
                if (r < 0)                                              \
                        log_syntax(unit, LOG_WARNING, filename, line, r, \
                                   msg ", ignoring: %s", rvalue);       \
                                                                        \
                return 0;                                               \
        }


/* Generic parsers */
CONFIG_PARSER_PROTOTYPE(config_parse_string);
CONFIG_PARSER_PROTOTYPE(config_parse_bool);
CONFIG_PARSER_PROTOTYPE(config_parse_sec);
