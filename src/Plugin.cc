/**
 * Generated S7 analyzer plugin class
 */

#include "Plugin.h"

namespace plugin { namespace Crysys_S7comm { Plugin plugin; } }

using namespace plugin::Crysys_S7comm;

plugin::Configuration Plugin::Configure()
	{
    AddComponent(new ::analyzer::Component("S7comm", ::analyzer::Crysys::S7comm_Analyzer::Instantiate));
	
    plugin::Configuration config;
	config.name = "Crysys::S7comm";
	config.description = "ISO-COTP on TPKT rfc 905 and S7 communication analyzer";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
