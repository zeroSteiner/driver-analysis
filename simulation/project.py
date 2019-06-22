import angr
import archinfo
import claripy

from . import engines
from . import jump_resolvers
from .procedures import windows_kernel

class WindowsDriverObjectFactory(angr.factory.AngrObjectFactory):
	def __init__(self, *args, **kwargs):
		super(WindowsDriverObjectFactory, self).__init__(*args, **kwargs)
		# set the default calling convention
		if isinstance(self.project.arch, archinfo.ArchAMD64):
			self._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64(self.project.arch)
		else:
			raise ValueError('unsupported project architecture')

	def call_state(self, addr, *args, **kwargs):
		kwargs['add_options'] = kwargs.pop('add_options', angr.options.unicorn)
		cc = kwargs.pop('cc', self._default_cc)
		kwargs['cc'] = cc
		if kwargs.pop('symbolic_register_arguments', False):
			args = list(args)
			while len(args) < len(cc.ARG_REGS):
				args.append(claripy.BVS('arg_' + str(len(args) + 1), cc.ARCH.bits))
		return super(WindowsDriverObjectFactory, self).call_state(addr, *args, **kwargs)

	def call_state_analysis(self, *args, **kwargs):
		kwargs['ret_addr'] = kwargs.pop('ret_addr', 0)
		state = self.call_state(*args, **kwargs)
		state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
		return state

	def simulation_manager_analysis(self, state, *args, **kwargs):
		simgr = self.simulation_manager(state.copy(), *args, **kwargs)
		cfg = self.project.analyses.CFGEmulated(
			indirect_jump_resolvers=jump_resolvers.factory(self.project),
			keep_state=False,
			max_iterations=5,
			normalize=True,
			starts=(state.copy(),),
		)
		simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
		return simgr

class WindowsDriverProject(angr.Project):
	def __init__(self, *args, **kwargs):
		kwargs['auto_load_libs'] = kwargs.pop('auto_load_libs', False)
		kwargs['use_sim_procedures'] = kwargs.pop('use_sim_procedures', False)
		super(WindowsDriverProject, self).__init__(*args, **kwargs)
		#self.engines.register_plugin(engines.SimEngineINT.name, engines.SimEngineINT(project=self))
		#self.engines.register_plugin(engines.SimEngineMSR.name, engines.SimEngineMSR(project=self))
		#self.engines.order = engines.factory_names()
		self.factory = WindowsDriverObjectFactory(self)
		for symbol, procedure in windows_kernel.procedures.items():
			self.hook_symbol(symbol, procedure(cc=self.default_cc))

	@property
	def default_cc(self):
		return self.factory._default_cc

	def address_to_offset(self, address):
		main_obj = self.loader.main_object
		if main_obj.contains_addr(address):
			return address - main_obj.mapped_base
		return None
