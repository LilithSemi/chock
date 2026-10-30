/* The module's own surface: reserve a buffer, run one query over one file, and
   read the rows back. Three exports, because the engine calls a function with
   at most three arguments. */

#include <tree_sitter/api.h>

const TSLanguage *ts_module_language(void);

void *malloc(size_t size);

/* The shim's heap. `free` gives nothing back, so every run gives back
   everything tree-sitter allocated during it, down to the mark above the
   buffers that have to live longer than one run. */
unsigned heap_mark(void);
void heap_reset(unsigned mark);

enum {
    max_source = 1u << 20,
    max_query = 1u << 16,
    max_input = max_source + max_query,
    max_rows = 4096,
    words_a_row = 6,
    max_captures = 256,
    name_bytes = 16384,
};

enum {
    failed_input = -1,
    failed_query = -2,
    failed_rows = -3,
    failed_memory = -4,
    failed_parse = -5,
};

static unsigned char *input_buffer;
static unsigned *rows;
static unsigned char *names;
static unsigned kept_mark;

static unsigned row_count;
static unsigned names_used;
/* Where a capture's name sits in `names`, and 0 for one not copied yet. */
static unsigned name_at[max_captures];

/* Allocated once each and never again, so the mark above them is stable and
   a run cannot free what the next run needs. */
static int reserve(void) {
    if (input_buffer == 0) input_buffer = malloc(max_input);
    if (rows == 0) rows = malloc(max_rows * words_a_row * sizeof(unsigned));
    if (names == 0) names = malloc(name_bytes);
    if (input_buffer == 0 || rows == 0 || names == 0) return 0;
    if (kept_mark == 0) kept_mark = heap_mark();
    return 1;
}

/* Room for the source and the query, which the host writes itself. */
unsigned char *ast_input(unsigned length) {
    if (!reserve()) return 0;
    if (length > max_input) return 0;
    return input_buffer;
}

/* The name's offset in linear memory, so the host reads it without a call. */
static unsigned nameFor(const TSQuery *query, unsigned capture) {
    if (capture >= max_captures) return 0;
    if (name_at[capture] != 0) return name_at[capture];

    unsigned length = 0;
    const char *text = ts_query_capture_name_for_id(query, capture, &length);
    if (text == 0 || length == 0 || names_used + length + 1 > name_bytes) return 0;

    unsigned char *into = names + names_used;
    for (unsigned at = 0; at < length; at++) into[at] = (unsigned char)text[at];
    into[length] = 0;
    name_at[capture] = (unsigned)(uintptr_t)into;
    names_used += length + 1;
    return name_at[capture];
}

int ast_run(unsigned source_length, unsigned query_length) {
    if (!reserve()) return failed_memory;
    if (source_length > max_source || query_length > max_query) return failed_input;
    if (source_length + query_length > max_input) return failed_input;

    /* Everything the last run left behind, before this one allocates. */
    heap_reset(kept_mark);

    row_count = 0;
    names_used = 0;
    for (unsigned at = 0; at < max_captures; at++) name_at[at] = 0;

    TSParser *parser = ts_parser_new();
    if (parser == 0) return failed_memory;
    if (!ts_parser_set_language(parser, ts_module_language())) {
        ts_parser_delete(parser);
        return failed_parse;
    }

    TSTree *tree = ts_parser_parse_string(
        parser, NULL, (const char *)input_buffer, source_length);
    if (tree == 0) {
        ts_parser_delete(parser);
        return failed_memory;
    }

    unsigned error_offset = 0;
    TSQueryError error_kind = TSQueryErrorNone;
    TSQuery *query = ts_query_new(
        ts_module_language(), (const char *)(input_buffer + source_length),
        query_length, &error_offset, &error_kind);
    if (query == 0) {
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return failed_query;
    }

    TSQueryCursor *cursor = ts_query_cursor_new();
    if (cursor == 0) {
        ts_query_delete(query);
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return failed_memory;
    }
    ts_query_cursor_exec(cursor, query, ts_tree_root_node(tree));

    int outcome = 0;
    TSQueryMatch match;
    while (ts_query_cursor_next_match(cursor, &match)) {
        for (unsigned at = 0; at < match.capture_count; at++) {
            if (row_count == max_rows) {
                outcome = failed_rows;
                break;
            }
            TSNode node = match.captures[at].node;
            TSPoint start = ts_node_start_point(node);
            TSPoint end = ts_node_end_point(node);
            unsigned *row = rows + (row_count * words_a_row);
            row[0] = nameFor(query, match.captures[at].index);
            row[1] = start.row;
            row[2] = start.column;
            row[3] = end.row;
            row[4] = end.column;
            row[5] = 0;
            row_count++;
        }
        if (outcome != 0) break;
    }

    ts_query_cursor_delete(cursor);
    ts_query_delete(query);
    ts_tree_delete(tree);
    ts_parser_delete(parser);
    if (outcome != 0) return outcome;
    return (int)row_count;
}

unsigned *ast_rows(void) {
    return rows;
}
