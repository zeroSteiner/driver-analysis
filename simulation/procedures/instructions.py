import logging

import angr

_reg_repr = lambda state, reg: "{0:08x}".format(state.solver.eval(reg)) if state.solver.unique(reg) else '????????'

class SimProcedureInstructionBase(angr.SimProcedure):
	IS_FUNCTION = False
	NO_RET = True

class SimProcedureRDMSR(SimProcedureInstructionBase):
	logger = logging.getLogger('simulation.procedures.instructions.rdmsr')
	def run(self, *args, **kwargs):
		if self.state.arch.name != 'AMD64':
			raise angr.errors.SimUnsupportedError('SimProcedureRDMSR is only implemented for AMD64')
		state = self.state
		state.regs.rax = state.solver.BVS('msr_lo_32', 32)
		state.regs.rdx = state.solver.BVS('msr_hi_32', 32)
		self.logger.info("Simulating 0x{0:x} rdmsr[0x{1}]".format(state.addr, _reg_repr(state, state.regs.rcx)))
		self.successors.add_successor(state, state.addr + 2, state.solver.true, 'Ijk_Boring')

class SimProcedureWRMSR(SimProcedureInstructionBase):
	logger = logging.getLogger('simulation.procedures.instructions.wrmsr')
	def run(self, *args, **kwargs):
		if self.state.arch.name != 'AMD64':
			raise angr.errors.SimUnsupportedError('SimProcedureWRMSR is only implemented for AMD64')
		state = self.state
		self.logger.info("Simulating 0x{0:x} wrmsr[0x{1}] = 0x{2}{3}".format(state.addr, _reg_repr(state, state.regs.rcx), _reg_repr(state, state.regs.rdx), _reg_repr(state, state.regs.rax)))
		self.successors.add_successor(state, state.addr + 2, state.solver.true, 'Ijk_Boring')
