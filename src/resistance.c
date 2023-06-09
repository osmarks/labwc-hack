// SPDX-License-Identifier: GPL-2.0-only
#include "config/rcxml.h"
#include "labwc.h"
#include "resistance.h"
#include "view.h"

struct edges {
	int left;
	int top;
	int right;
	int bottom;
};

static void
is_within_resistance_range(struct edges view, struct edges target,
		struct edges other, struct edges *flags, int strength)
{
	if (view.left >= other.left && target.left < other.left
			&& target.left >= other.left - strength) {
		flags->left = 1;
	} else if (view.right <= other.right && target.right > other.right
			&& target.right <= other.right + strength) {
		flags->right = 1;
	}

	if (view.top >= other.top && target.top < other.top
			&& target.top >= other.top - strength) {
		flags->top = 1;
	} else if (view.bottom <= other.bottom && target.bottom > other.bottom
			&& target.bottom <= other.bottom + strength) {
		flags->bottom = 1;
	}
}

void
resistance_move_apply(struct view *view, double *x, double *y)
{
	struct server *server = view->server;
	struct wlr_box mgeom, intersection;
	struct wlr_box vgeom = view->current;
	struct wlr_box tgeom = {.x = *x, .y = *y, .width = vgeom.width,
		.height = vgeom.height};
	struct output *output;
	struct border border = ssd_get_margin(view->ssd);
	struct edges view_edges; /* The edges of the current view */
	struct edges target_edges; /* The desired edges */
	struct edges other_edges; /* The edges of the monitor/other view */
	struct edges flags = { 0 };

	view_edges.left = vgeom.x - border.left + 1;
	view_edges.top = vgeom.y - border.top + 1;
	view_edges.right = vgeom.x + vgeom.width + border.right;
	view_edges.bottom = vgeom.y + vgeom.height + border.bottom;

	target_edges.left = *x - border.left;
	target_edges.top = *y - border.top;
	target_edges.right = *x + vgeom.width + border.right;
	target_edges.bottom = *y + vgeom.height + border.bottom;

	if (!rc.screen_edge_strength) {
		return;
	}

	wl_list_for_each(output, &server->outputs, link) {
		if (!output_is_usable(output)) {
			continue;
		}

		mgeom = output_usable_area_in_layout_coords(output);

		if (!wlr_box_intersection(&intersection, &vgeom, &mgeom)
				&& !wlr_box_intersection(&intersection, &tgeom,
				&mgeom)) {
			continue;
		}

		other_edges.left = mgeom.x;
		other_edges.top = mgeom.y;
		other_edges.right = mgeom.x + mgeom.width;
		other_edges.bottom = mgeom.y + mgeom.height;

		is_within_resistance_range(view_edges, target_edges,
			other_edges, &flags, rc.screen_edge_strength);

		if (flags.left == 1) {
			*x = other_edges.left + border.left;
		} else if (flags.right == 1) {
			*x = other_edges.right - vgeom.width - border.right;
		}

		if (flags.top == 1) {
			*y = other_edges.top + border.top;
		} else if (flags.bottom == 1) {
			*y = other_edges.bottom - vgeom.height - border.bottom;
		}

		/* reset the flags */
		flags.left = 0;
		flags.top = 0;
		flags.right = 0;
		flags.bottom = 0;
	}
}

void
resistance_resize_apply(struct view *view, struct wlr_box *new_view_geo)
{
	struct server *server = view->server;
	struct output *output;
	struct wlr_box mgeom, intersection;
	struct wlr_box vgeom = view->current;
	struct wlr_box tgeom = *new_view_geo;
	struct border border = ssd_get_margin(view->ssd);
	struct edges view_edges; /* The edges of the current view */
	struct edges target_edges; /* The desired edges */
	struct edges other_edges; /* The edges of the monitor/other view */
	struct edges flags = { 0 };

	view_edges.left = vgeom.x - border.left;
	view_edges.top = vgeom.y - border.top;
	view_edges.right = vgeom.x + vgeom.width + border.right;
	view_edges.bottom = vgeom.y + vgeom.height + border.bottom;

	target_edges.left = new_view_geo->x - border.left;
	target_edges.top = new_view_geo->y - border.top;
	target_edges.right = new_view_geo->x + new_view_geo->width
		+ border.right;
	target_edges.bottom = new_view_geo->y + new_view_geo->height
		+ border.bottom;

	if (!rc.screen_edge_strength) {
		return;
	}
	wl_list_for_each(output, &server->outputs, link) {
		if (!output_is_usable(output)) {
			continue;
		}

		mgeom = output_usable_area_in_layout_coords(output);

		if (!wlr_box_intersection(&intersection, &vgeom, &mgeom)
				&& !wlr_box_intersection(&intersection, &tgeom,
				&mgeom)) {
			continue;
		}

		other_edges.left = mgeom.x;
		other_edges.top = mgeom.y;
		other_edges.right = mgeom.x + mgeom.width;
		other_edges.bottom = mgeom.y + mgeom.height;

		is_within_resistance_range(view_edges, target_edges,
			other_edges, &flags, rc.screen_edge_strength);

		if (server->resize_edges & WLR_EDGE_LEFT) {
			if (flags.left == 1) {
				new_view_geo->x = other_edges.left
					+ border.left;
				new_view_geo->width = vgeom.width;
			}
		} else if (server->resize_edges & WLR_EDGE_RIGHT) {
			if (flags.right == 1) {
				new_view_geo->width = other_edges.right
					- view_edges.left - border.right
					- border.left;
			}
		}

		if (server->resize_edges & WLR_EDGE_TOP) {
			if (flags.top == 1) {
				new_view_geo->y = other_edges.top + border.top;
				new_view_geo->height = vgeom.height;
			}
		} else if (server->resize_edges & WLR_EDGE_BOTTOM) {
			if (flags.bottom == 1) {
				new_view_geo->height =
					other_edges.bottom - view_edges.top
					- border.bottom - border.top;
			}
		}

		/* reset the flags */
		flags.left = 0;
		flags.top = 0;
		flags.right = 0;
		flags.bottom = 0;
	}
}
