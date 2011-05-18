#ifndef __GRAPH_H__
#define __GRAPH_H__

typedef struct _me_graph_node {
	unsigned long	id;						// id = address of instruction.
//	uchar	type;					// One of C_JMP, C_JMC, C_CAL, C_RET
	struct	_me_graph_node *adj;	// adjacent nodes
	unsigned long	nhit;					// number of times address was accessed.
	int		condition;
	struct	_me_graph_node *next;	// next node in the list
} ME_GRAPH_NODE;

typedef struct _me_graph {
	ME_GRAPH_NODE *nodes;
} ME_GRAPH;


ME_GRAPH_NODE *graph_add_node (ME_GRAPH *graph, unsigned long from, unsigned long to, int condition);

#endif