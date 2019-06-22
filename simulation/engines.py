import angr

from . import procedures

def factory(project):
	engines = (
		SimEngineINT(project),
		angr.engines.SimEngineFailure(project),
		angr.engines.SimEngineSyscall(project),
		angr.engines.SimEngineHook(project),
		SimEngineMSR(project),
		angr.engines.SimEngineUnicorn(project),
		angr.engines.SimEngineVEX(project),
	)
	return engines

def factory_names():
	return ('int', 'failure', 'syscall', 'hook', 'msr', 'unicorn', 'vex')

class SimEngineINT(angr.SimEngine):
	name = 'int'
	def check(self, state, *args, **kwargs):
		jumpkind = state.history.jumpkind
		if not jumpkind.startswith('Ijk_Sys_int'):
			return False
		return self._get_handler(jumpkind) is not None

	def process(self, state, force_addr=None, **kwargs):
		handler = self._get_handler(state.history.jumpkind)
		return handler(state, force_addr=force_addr, **kwargs)

	def _get_handler(self, jumpkind):
		return getattr(self, "_int_0x{0:x}".format(int(jumpkind[11:])), None)

	def _int_0x29(self, state, force_addr=None, **kwargs):
		# https://doar-e.github.io/blog/2013/10/12/having-a-look-at-the-windows-userkernel-exceptions-dispatcher/
		terminator = angr.procedures.SIM_PROCEDURES['stubs']['PathTerminator'](project=self.project)
		return self.project.factory.procedure_engine.process(state, terminator, force_addr=state.addr)

class SimEngineMSR(angr.SimEngine):
	name = 'msr'
	def check(self, state, *args, **kwargs):
		return self.process(state, *args, **kwargs) is not None

	def process(self, state, force_addr=None, **kwargs):
		addr = state.addr if force_addr is None else force_addr
		rip_word = state.mem[addr].word
		procedure = None
		if rip_word.concrete == 0x300f:  # wrmsr
			procedure = procedures.SimProcedureWRMSR
		if rip_word.concrete == 0x320f:  # rdmsr
			procedure = procedures.SimProcedureRDMSR
		if procedure is None:
			return None
		procedure = procedure(project=state.project)
		return self.project.factory.procedure_engine.process(state, procedure, force_addr=force_addr, **kwargs)

angr.engines.basic_preset.add_default_plugin(SimEngineINT.name, SimEngineINT)
angr.engines.basic_preset.add_default_plugin(SimEngineMSR.name, SimEngineMSR)
