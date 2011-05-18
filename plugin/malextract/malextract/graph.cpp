#include <stdio.h>
#include <stdlib.h>
#include "graph.h"

ME_GRAPH_NODE *graph_add_node (ME_GRAPH *graph, unsigned long from, unsigned long to, int condition)
{
	ME_GRAPH_NODE *new_node;

	if (graph->nodes == NULL) {
		graph->nodes = (ME_GRAPH_NODE *) malloc (sizeof (ME_GRAPH_NODE));
		graph->nodes->next = NULL;
		graph->nodes->id = from;
		graph->nodes->nhit = 1;
		graph->nodes->condition = condition;

		new_node = (ME_GRAPH_NODE *) malloc (sizeof (ME_GRAPH_NODE));
		new_node->adj = NULL;
		new_node->condition = 0xff;
		new_node->id = to;
		new_node->nhit = 0;
		new_node->next = NULL;

		graph->nodes->adj = new_node;
	}

}