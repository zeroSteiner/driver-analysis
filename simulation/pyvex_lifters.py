import pyvex
import pyvex.lifting.util

_Type = pyvex.lifting.util.Type
_VexValue = pyvex.lifting.util.syntax_wrapper.VexValue

class Instruction_INT(pyvex.lifting.util.instr_helper.Instruction):
	name = 'int'
	bin_format = '11001101xxxxxxxx'
	def compute_result(self):
		number = int(self.data['x'], 2)
		# https://github.com/angr/vex/blob/4bdf4da8e0208e8ebf0a728d0477aebfba890f93/pub/libvex_ir.h#L2285-L2352
		self.jump(None, self.irsb_c.irsb.addr + 2, jumpkind='Ijk_Sys_int' + str(number))


class Instruction_RDMSR(pyvex.lifting.util.instr_helper.Instruction):
	name = 'rdmsr'
	bin_format = '0000111100110010'
	def compute_result(self):
		self.get('ecx', _Type.int_32)
		# TODO: these shouldn't be using constants
		self.put(_VexValue.Constant(self.irsb_c, 1, _Type.int_32), 'eax')
		self.put(_VexValue.Constant(self.irsb_c, 1, _Type.int_32), 'edx')
		return True

	def commit_result(self, retval):
		ir_const_class = pyvex.const.vex_int_class(self.irsb_c.arch.bits)
		self.irsb_c.irsb.next = pyvex.expr.Const(ir_const_class(self.irsb_c.irsb.addr + 2))

class Instruction_WRMSR(pyvex.lifting.util.instr_helper.Instruction):
	name = 'wrmsr'
	bin_format = '0000111100110000'
	def compute_result(self):
		#self.get('ecx', _Type.int_32)
		#self.get('eax', _Type.int_32)
		#self.get('edx', _Type.int_32)
		return True

class AMD64Spotter(pyvex.lifting.util.lifter_helper.GymratLifter):
	instrs = (
		Instruction_INT,
		Instruction_RDMSR,
		#Instruction_WRMSR
	)

pyvex.lifting.register(AMD64Spotter, 'AMD64')
