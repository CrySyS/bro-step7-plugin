/**
 * Header file for the S7 protocol analyzer
 */
#ifndef BRO_PLUGIN_CRYSYS_S7COMM
#define BRO_PLUGIN_CRYSYS_S7COMM

#include <plugin/Plugin.h>
#include "S7comm.h"

namespace plugin {
namespace Crysys_S7comm {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
