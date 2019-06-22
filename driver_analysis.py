#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
#  driver_analysis.py
#
#  Copyright 2018 Spencer McIntyre <zeroSteiner@gmail.com>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# this script must be run with Python 2.7 (for the angr library) and is thus not
# meant to use the same 3.x runtime environment as the larger project

# phase 1 - setup
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import collections
import datetime
import hashlib
import json
import logging
import os
import re
import signal
import sys

import angr
import archinfo
import boltons.timeutils
import claripy
import smoke_zephyr.argparse_types
import tabulate

import simulation

__version__ = '1.0'

DOS_DEVICES = '\\DosDevices\\'.encode('utf-16le')

# https://msdn.microsoft.com/en-us/library/cc704588.aspx
STATUS_SUCCESS               = 0
STATUS_NOT_IMPLEMENTED       = 0xc0000002
STATUS_INVALID_HANDLE        = 0xc0000008
STATUS_INVALID_PARAMETER     = 0xc000000d
STATUS_NOT_SUPPORTED         = 0xc00000bb

HASH_ALGORITHMS = ('md5', 'sha1', 'sha256')

def ast_repr(node):
	if not isinstance(node, claripy.ast.Base):
		raise TypeError('node must be an instance of claripy.ast.Base not: ' + repr(node))
	return re.sub(r'([^a-zA-Z][a-zA-Z]+)_\d+_\d+([^\d]|$)', r'\1\2', node.__repr__(inner=True))

def ioctl_state_to_dict(project, state, IoStackLocation):
	in_var = ast_repr(IoStackLocation.fields['InputBufferLength'])
	out_var = ast_repr(IoStackLocation.fields['OutputBufferLength'])

	in_constraints = []
	out_constraints = []
	for constraint in state.solver.constraints:
		str_constraint = ast_repr(constraint)
		if 'InputBufferLength' in str_constraint:
			in_constraints.append(str_constraint)
		elif 'OutputBufferLength' in str_constraint:
			out_constraints.append(str_constraint)
	trace_addresses = tuple(project.address_to_offset(address) for address in state.history.bbl_addrs)
	trace_addresses = tuple(filter(lambda address: address is not None, trace_addresses))

	value = {
		'constraints': in_constraints + out_constraints,
		'ioctl': state.solver.eval(IoStackLocation.fields['IoControlCode']),
		'trace': {
			'address-type': {
				'data': 'basic-block',
				'relation': 'offset',
			},
			'addresses': trace_addresses,
		}
	}
	return value

def find_utf_16le_str(data, string):
	cursor = 0
	found = collections.deque()
	while cursor < len(data):
		cursor = data.find(string, cursor)
		if cursor == -1:
			break
		terminator = data.find(b'\x00\x00', cursor)
		if (terminator - cursor) % 2:
			terminator += 1
		match = data[cursor:terminator].decode('utf-16le')
		if not match in found:
			yield match
			found.append(match)
		cursor += len(string)

def find_device_names(path):
	with open(path, 'rb') as file_h:
		data = file_h.read()
	return tuple(find_utf_16le_str(data, DOS_DEVICES))

def find_driver_object(project):
	arg_driverobject = 0xdead0000
	arg_registrypath = 0xdead1000

	# create our state for DriverEntry(pDriveObject, pRegistryPath)
	# with a return address of 0 so it's easily identifiable
	entry_state = project.factory.call_state_analysis(
		project.entry,
		arg_driverobject,
		arg_registrypath,
	)

	driver_object = simulation.structures.DRIVER_OBJECT(entry_state, arg_driverobject)
	entry_state.solver.add(driver_object.fields['DeviceObject'] == 0)
	entry_state.solver.add(driver_object.fields['DriverStart'] == project.loader.main_object.mapped_base)
	entry_state.solver.add(driver_object.fields['DriverInit'] == project.loader.main_object.entry)
	entry_state.solver.add(driver_object.fields['DriverStartIo'] == 0)
	entry_state.solver.add(driver_object.fields['DriverUnload'] == 0)

	simgr = project.factory.simulation_manager_analysis(entry_state)

	# http://angr.io/api-doc/angr.html#angr.exploration_techniques.spiller.Spiller
	simgr.use_technique(angr.exploration_techniques.spiller.Spiller(min=50, max=100, staging_stash='overflow', staging_min=100, staging_max=200))
	simgr.explore(
		engines=simulation.engines.factory(project), find=0, num_find=float('inf')
	)
	if simgr.errored:
		print("[-] {0:,} states resulted in an error condition".format(len(simgr.errored)))
		import ipdb; ipdb.set_trace()

	# iterate though the found states and check the value of
	# pDriverObject->MajorFunction[14] (DeviceControl)
	if not isinstance(project.arch, archinfo.ArchAMD64):
		raise RuntimeError('must update offsets for non AMD64 architectures')

	major_functions = {}
	if not simgr.found:
		return None
	for state in simgr.found:
		for idx in range(28):
			value = state.mem[arg_driverobject + 0x70 + (8 * idx)].qword
			if value.resolved.symbolic:
				continue
			value = project.address_to_offset(value.concrete)
			if value is None:
				continue
			if idx in major_functions and major_functions[idx] != value:
				major_functions[idx] = None
			else:
				major_functions[idx] = value
	major_functions = [major_functions.get(idx) for idx in range(28)]
	driver_object = driver_object.to_dict(state)
	driver_object['fields'].append({'name': 'MajorFunction', 'type': 'void* MajorFunction[28]', 'value': major_functions})
	return driver_object

def find_valid_ioctl_states(project, mj_device_control):
	arg_deviceobject = 0xdead0000
	arg_irp = 0xdead8000
	entry_state = project.factory.call_state_analysis(
		project.loader.main_object.mapped_base + mj_device_control,
		arg_deviceobject,
		arg_irp,
	)

	io_stack_location = simulation.structures.IO_STACK_LOCATION(entry_state, 0xdeadc000)
	irp = simulation.structures.IRP(entry_state, arg_irp)
	entry_state.solver.add(irp.fields['Type'] == 6)
	entry_state.solver.add(irp.fields['MdlAddress'] == 0)
	entry_state.solver.add(irp.fields['IoStatus.Status'] == STATUS_SUCCESS)
	entry_state.solver.add(irp.fields['IoStatus.Information'] == 0)
	entry_state.solver.add(irp.fields['RequestorMode'] == 1)
	entry_state.solver.add(irp.fields['PendingReturned'] == 0)
	entry_state.solver.add(irp.fields['StackCount'] == 1)
	entry_state.solver.add(irp.fields['CurrentLocation'] == 1)
	entry_state.solver.add(irp.fields['Cancel'] == 0)
	entry_state.solver.add(irp.fields['CancelIrql'] == 0)
	entry_state.solver.add(irp.fields['ApcEnvironment'] == 0)
	entry_state.solver.add(irp.fields['AllocationFlags'] == 6)
	entry_state.solver.add(irp.fields['UserEvent'] == 0)
	entry_state.solver.add(irp.fields['CancelRoutine'] == 0)
	entry_state.solver.add(irp.fields['Tail.Overlay.CurrentStackLocation'] == io_stack_location.address)

	entry_state.solver.add(io_stack_location.fields['MajorFunction'] == 14)
	entry_state.solver.add(io_stack_location.fields['MinorFunction'] == 0)
	entry_state.solver.add(io_stack_location.fields['Flags'] == 5)
	entry_state.solver.add(io_stack_location.fields['Control'] == 0)
	entry_state.solver.add(io_stack_location.fields['DeviceObject'] == arg_deviceobject)
	entry_state.solver.add(io_stack_location.fields['CompletionRoutine'] == 0)
	entry_state.solver.add(io_stack_location.fields['Context'] == 0)

	simgr = project.factory.simulation_manager_analysis(entry_state)
	# http://angr.io/api-doc/angr.html#angr.exploration_techniques.spiller.Spiller
	simgr.use_technique(angr.exploration_techniques.spiller.Spiller(min=50, max=100, staging_stash='overflow', staging_min=100, staging_max=200))

	def _avoid(state):
		status = irp.read_field_single_valued('IoStatus.Status', state=state)
		return status is not None and status != 0

	def _find(state):
		eval_ = state.solver.eval
		unique_ = state.solver.unique
		if eval_(state.regs.rip) != 0:
			return False

		if irp.read_field_single_valued('IoStatus.Status', state=state):
			return False
		# check if IoControlCode is concrete or symbolic
		if not unique_(io_stack_location.fields['IoControlCode']):
			return False
		return True

	def _step_func(lsm):
		lsm = lsm.drop(stash='avoid')
		return lsm

	simgr.explore(
		avoid=_avoid,
		engines=simulation.engines.factory(project),
		find=_find,
		num_find=float('inf'),
		step_func=_step_func
	)
	if simgr.errored:
		print("[-] {0:,} states resulted in an error condition".format(len(simgr.errored)))
		import ipdb; ipdb.set_trace()

	found_states = sorted(simgr.found, key=lambda state: state.solver.eval(io_stack_location.fields['IoControlCode']))
	return tuple(ioctl_state_to_dict(project, state, io_stack_location) for state in found_states)

def print_valid_ioctl_states(found_states):
	table = []
	for idx, state in enumerate(found_states, 1):
		constraints = ' && '.join(state['constraints'])
		table.append((idx, "0x{0:08x}".format(state['ioctl']), '', constraints))
	table = sorted(table, key=lambda row: row[0])
	print(tabulate.tabulate(table, headers=('#', 'IOCTL Code', 'Name', 'Constraints'), tablefmt='pipe'))

	summary = "Summary: {0:,} states found ({1:,} unique IOCTL values)".format(
		len(table),
		len(set(state['ioctl'] for state in found_states))
	)
	print('-' * len(summary))
	print(summary)

def setup_logging(args):
	level = getattr(logging, args.loglvl)
	root_logger = logging.getLogger('')
	for handler in root_logger.handlers:
		root_logger.removeHandler(handler)

	logging.getLogger(args.logger).setLevel(logging.DEBUG)
	console_log_handler = logging.StreamHandler()
	console_log_handler.setLevel(level)
	console_log_handler.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
	logging.getLogger(args.logger).addHandler(console_log_handler)
	logging.captureWarnings(True)

def sigalrm_handler(*args, **kwargs):
	raise TimeoutError('sigalrm raised')

def main():
	start_time = datetime.datetime.utcnow()
	parser = argparse.ArgumentParser(description='Automatic Driver Analysis', conflict_handler='resolve')
	parser.add_argument('driver', help='the driver to analyze')
	parser.add_argument('-o', '--output', default=None, help='the file to write the analysis data to')
	parser.add_argument('--timeout', type=smoke_zephyr.argparse_types.timespan_type, help='an optional operation timeout')
	parser.add_argument('-L', '--log', default='FATAL', dest='loglvl', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL'), help='set the logging level')
	parser.add_argument('--logger', default='', help='specify the root logger')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + __version__)
	args = parser.parse_args()

	setup_logging(args)
	if not os.path.isfile(args.driver):
		print('[-] invalid driver file: ' + args.driver)
		return os.EX_DATAERR
	driver_offset = lambda offset: "{0}+0x{1:x}".format(os.path.splitext(os.path.basename(args.driver))[0], offset)

	if args.timeout:
		signal.signal(signal.SIGALRM, sigalrm_handler)
		signal.alarm(args.timeout)

	print('[*] basic driver file information:')
	with open(args.driver, 'rb') as file_h:
		data = file_h.read()
		hashes = collections.OrderedDict((algo, hashlib.new(algo, data).hexdigest()) for algo in HASH_ALGORITHMS)
	for algo, digest in hashes.items():
		print("  * {0: <8} {1}".format(algo + ':', digest))

	device_names = find_device_names(args.driver)
	print("[*] identified {0:,} device names".format(len(device_names)))
	for device_name in device_names:
		print('  * ' + device_name)

	project = simulation.WindowsDriverProject(args.driver)
	analysis = {
		'binary': {
			'architecture': project.arch.name,
			'base-address': project.loader.main_object.mapped_base,
			'hashes': hashes,
			'name': os.path.basename(args.driver),
			'size': os.stat(args.driver).st_size,
		},
		'created': start_time.isoformat() + '+00:00',
		'device-names': device_names,
	}

	driver_object = find_driver_object(project)
	if driver_object is None:
		print('[-] failed to identify the driver object')
		return os.EX_SOFTWARE
	analysis['driver-object'] = driver_object
	mj_device_control = next(field for field in driver_object['fields'] if field['name'] == 'MajorFunction')
	mj_device_control = mj_device_control['value'][14]
	if mj_device_control is None:
		print('[-] failed to identify a single concrete value for the control routine')
	else:
		print("[+] identified {0} as the control routine".format(driver_offset(mj_device_control)))

		ioctl_states = find_valid_ioctl_states(project, mj_device_control)
		analysis['ioctl-states'] = ioctl_states
		print_valid_ioctl_states(ioctl_states)

	results_file = args.output or os.path.splitext(os.path.basename(args.driver))[0] + '-analysis.json'
	with open(results_file, 'w') as file_h:
		json.dump(analysis, file_h, indent=2, separators=(',', ': '), sort_keys=True)
	elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
	print("[*] completed in: {0:.1f} {1}".format(*elapsed))
	return os.EX_OK

if __name__ == '__main__':
	sys.exit(main())
