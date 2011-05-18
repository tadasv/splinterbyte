#ifndef __MALEXTRACT_H__
#define __MALEXTRACT_H__ 1

#include "plugin.h"
//#include "helpers.h"
#include "graph.h"
#include <vector>

// Memory owned by a particular module
typedef struct _me_module_range
{
	ulong start;
	ulong size;
} ME_MODULE_RANGE;

typedef struct _me_context
{
	int invoked;
	t_thread *thread;
	t_module *module;
	unsigned char *imagecopy;
	std::vector<ME_MODULE_RANGE> module_ranges;

} ME_CONTEXT;

#endif