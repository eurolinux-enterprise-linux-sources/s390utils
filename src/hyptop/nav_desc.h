/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Description of navigation keys
 *
 * Copyright IBM Corp. 2010
 * Author(s): Michael Holzheu <holzheu@linux.vnet.ibm.com>
 */

#ifndef NAV_DESC_H
#define NAV_DESC_H

#include "tbox.h"

struct nav_desc {
	char	*desc;
	char	*keys[];
};

void nav_desc_add(struct tbox *tb,
		  struct nav_desc **desc_normal,
		  struct nav_desc **desc_select,
		  struct nav_desc **desc_general);

struct nav_desc nav_desc_quit;
struct nav_desc nav_desc_select_mode_enter;
struct nav_desc nav_desc_select_mode_leave;
struct nav_desc nav_desc_win_enter_sys;
struct nav_desc nav_desc_win_leave_sys;
struct nav_desc nav_desc_win_leave_sys_fast;
struct nav_desc nav_desc_win_enter_fields;
struct nav_desc nav_desc_win_leave_fields;
struct nav_desc nav_desc_win_leave_fields_fast;
struct nav_desc nav_desc_win_enter_cpu_types;
struct nav_desc nav_desc_win_leave_cpu_types;
struct nav_desc nav_desc_win_leave_cpu_types_fast;
struct nav_desc nav_desc_marks_clear;
struct nav_desc nav_desc_mark_toggle;
struct nav_desc nav_desc_mark_toggle_view;
struct nav_desc nav_desc_col_unit_increase;
struct nav_desc nav_desc_col_unit_decrease;
struct nav_desc nav_desc_row_unit_increase;
struct nav_desc nav_desc_row_unit_decrease;
struct nav_desc nav_desc_select_col_next;
struct nav_desc nav_desc_select_col_prev;
struct nav_desc nav_desc_select_col_hotkey;
struct nav_desc nav_desc_toggle_mark_hotkey;
struct nav_desc nav_desc_scroll_up_line;
struct nav_desc nav_desc_scroll_down_line;
struct nav_desc nav_desc_scroll_up_page;
struct nav_desc nav_desc_scroll_down_page;
struct nav_desc nav_desc_scroll_up_head;
struct nav_desc nav_desc_scroll_down_tail;

#endif /* NAV_DESC_H */
