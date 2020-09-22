##! Load Intel Framework
@load policy/integration/collective-intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
redef Intel::read_files += {
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/abuse-ch-ipblocklist.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/alienvault.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/binarydefense.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/compromised-ips.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/covid.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/dom-bl.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/illuminate.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/openphish.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/predict_intel.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/rutgers.intel",
	"/opt/zeek/share/zeek/site/Zeek-Intelligence-Feeds/tor-exit.intel"
};
