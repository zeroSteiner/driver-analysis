import logging

import angr

STATUS_SUCCESS = 0

procedures = {}
def register(procedure):
	procedures[procedure.__name__] = procedure
	return procedure

class WindowsKernelSimProcedure(angr.SimProcedure):
	def __init__(self, *args, **kwargs):
		super(WindowsKernelSimProcedure, self).__init__(*args, **kwargs)
		self.logger = logging.getLogger('simulation.procedures.windows.kernel.' + self.__class__.__name__)

@register
class IoCreateDevice(WindowsKernelSimProcedure):
	def run(self, driver_object, device_extension_size, device_name, device_type, device_characteristics, exclusive, device_object):
		self.logger.warning("IoCreateDevice(%s, %s, %s, %s, %s, %s, %s)", driver_object, device_extension_size, device_name, device_type, device_characteristics, exclusive, device_object)
		return STATUS_SUCCESS

@register
class IoCreateSymbolicLink(WindowsKernelSimProcedure):
	def run(self, symbolic_link_name, device_name):
		self.logger.warning("IoCreateSymbolicLink(%s, %s)", symbolic_link_name, device_name)
		return STATUS_SUCCESS

@register
class IofCompleteRequest(WindowsKernelSimProcedure):
	def run(self, irp, priority_boost):
		self.logger.warning("IofCompleteRequest(%s, %s)", irp, priority_boost)
		return self.state.solver.Unconstrained('IofCompleteRequest', self.state.arch.bits)

@register
class PsGetVersion(WindowsKernelSimProcedure):
	def run(self, major_version, minor_version, build_number, csd_version):
		self.logger.warning("PsGetVersion(%s, %s, %s, %s)", major_version, minor_version, build_number, csd_version)
		if major_version:
			self.state.mem[major_version].dword = 10
		if minor_version:
			self.state.mem[minor_version].dword = 0
		if build_number:
			self.state.mem[build_number].dword = 0x42ee
		return self.state.solver.BVV(0, 8)

@register
class PsSetCreateProcessNotifyRoutine(WindowsKernelSimProcedure):
	def run(self, notify_routine, remove):
		self.logger.warning("PsSetCreateProcessNotifyRoutine(%s, %s)", notify_routine, remove)
		return STATUS_SUCCESS
