import logging

import angr.analyses.cfg.indirect_jump_resolvers.default_resolvers
import angr.analyses.cfg.indirect_jump_resolvers.resolver
import smoke_zephyr.utilities

def factory(project, obj=None):
	obj = obj or project.loader.main_object
	indirect_jump_resolvers = tuple(
		angr.analyses.cfg.indirect_jump_resolvers.default_resolvers.default_indirect_jump_resolvers(
			obj,
			project
		)) + (SimulationResolver(project),)
	return indirect_jump_resolvers

class SimulationResolver(angr.analyses.cfg.indirect_jump_resolvers.resolver.IndirectJumpResolver):
	logger = logging.getLogger('simulation.jump_resolvers.SimulationResolver')
	def __init__(self, *args, **kwargs):
		self.__cache = {}
		super(SimulationResolver, self).__init__(*args, **kwargs)

	def filter(self, cfg, addr, func_addr, block, jumpkind):
		return jumpkind == 'Ijk_Boring'

	def _resolve(self, cfg, addr, func_addr, block, jumpkind):
		call_state = self.project.factory.call_state(func_addr, symbolic_register_arguments=True)
		simgr = self.project.factory.simulation_manager(call_state)
		simgr.explore(find=addr)
		if not simgr.found:
			return False, None
		simgr.move('active', 'pruned')
		simgr.move('found', 'active')
		simgr.step()
		return True, sorted(smoke_zephyr.utilities.unique(tuple(state.addr for state in simgr.active)))

	def resolve(self, cfg, addr, func_addr, block, jumpkind):
		cache_key = (id(cfg), addr, func_addr)
		results = self.__cache.get(cache_key)
		if results is None:
			results = self._resolve(cfg, addr, func_addr, block, jumpkind)
			self.__cache[cache_key] = results
		return results
