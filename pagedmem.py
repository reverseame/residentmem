import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.constants as constants
import volatility.exceptions as exceptions
import volatility.win32.modules as modules
from volatility.plugins.common import AbstractWindowsCommand
import volatility.conf as conf
import volatility.commands as commands
import volatility.registry as registry
import os

# TODO allow to define PAGE_SIZE by parameter
PAGE_SIZE = 4096

class PagedMem(AbstractWindowsCommand):
    """ XXX: List of valid pages """

    def __init__(self, config, *args, **kwargs):
        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option='D', help='Directory in which to dump files', action='store', type='str')
        self._config.add_option('PID', short_option='p', help='Process ID', action='store',type='str')
        self._config.add_option('LOGFILE', help='Logfile to dump full info', action='store',type='str')

    
    def process_memspace(self, task_space, mod, dump_filename):
        
        count_valid_pages = 0
        
        # Create dump_file, if needed
        dump_file = None
        f = None
        if self._config.DUMP_DIR:
            dump_file = dump_filename
            os.path.join(self._config.DUMP_DIR,'{0}-{1}-{2}.csv'.format(task.ImageFileName, task.UniqueProcessId, mod.BaseDllName.v()))
            f = open(dump_file, "w+")
            f.write("VADDR,PHYADDR\n") # CSV header
                    
        # iterate on memory pages and count resident ones
        for i in range(0, mod.SizeOfImage, PAGE_SIZE):
            phyaddr = task_space.vtop(mod.DllBase+i)
            if phyaddr:
                count_valid_pages += 1
                if self._config.DUMP_DIR: 
                    f.write("{},{}\n".format(hex(mod.DllBase+i)[:-1],hex(phyaddr)[:-1]))
                    
        # compute the total pages and yield the result
        total_pages = mod.SizeOfImage / PAGE_SIZE
        return [mod.BaseDllName.v(), mod.DllBase.v(), total_pages - count_valid_pages, total_pages, mod.FullDllName.v(), dump_file if dump_file else None]

    def iterate_umemspace(self, task):
        """ Iterates in the memory space of the given task, computing the valid pages """
        
        retdata = []
        task_space = task.get_process_address_space()
        for mod in task.get_load_modules():
            _filename = None
            if self._config.DUMP_DIR:
                _filename = os.path.join(self._config.DUMP_DIR,'{0}-{1}-{2}.csv'.format(task.ImageFileName, task.UniqueProcessId, mod.BaseDllName.v()))
            _moddata = self.process_memspace(task_space, mod, _filename)
            
            _auxdata = [task.UniqueProcessId, task.ImageFileName]
            _auxdata.extend(_moddata)
            retdata.append(_auxdata)

            if self._config.DUMP_DIR: 
                f.close()

        return retdata

    def iterate_kmemspace(self, task_space, driver):

        retdata = []
        _filename = None
        if self._config.DUMP_DIR:
            _filename = os.path.join(self._config.DUMP_DIR,'driver-{}.csv'.format(mod.BaseDllName.v()))
        _moddata = self.process_memspace(task_space, driver, _filename)
        _auxdata = ['--', '--']
        _auxdata.extend(_moddata)
        retdata.append(_auxdata)

        return retdata

    def calculate(self):
        """ TODO """

        self.addr_space = utils.load_as(self._config)
        if self._config.PID:
            pids = self._config.PID.split(',')

        # check logfile output
        f = None
        if self._config.LOGFILE:
            log_file = os.path.join(self._config.LOGFILE)
            f = open(log_file, "w+")

        # iterate on tasks
        tasks_info = []
        for task in tasks.pslist(self.addr_space):
            if (not self._config.PID) or (str(task.UniqueProcessId) in pids):
                _task_data = self.iterate_umemspace(task)
                tasks_info.extend(_task_data) # join to the result data
                if f: # output data to logfile, if provided
                    for item in _task_data: # we follow TSV format
                        for element in item[:-1]:
                            f.write(str(element) + '\t')
                        f.write(str(item[-1]) + '\n')
        
        # TODO Set this by an optional parameter
        # iterate on drivers
        mods = dict((mod.DllBase.v(), mod) for mod in modules.lsmod(self.addr_space))
        for mod in mods.values():
            _task_data = self.iterate_kmemspace(self.addr_space, mod)
            tasks_info.extend(_task_data) # join to the result data
            if f: # output data to logfile, if provided
                for item in _task_data: # we follow TSV format
                    for element in item[:-1]:
                        f.write(str(element) + '\t')
                    f.write(str(item[-1]) + '\n')

        # cleanup
        if self._config.LOGFILE:
            f.close()

        return tasks_info

    def unified_output(self, data):
        if self._config.DUMP_DIR:
            return renderers.TreeGrid([
                        ('Pid', '4'),
                        ('Process', '12'),
                        ('Module Name', '20'),
                        ('Module Base', '[addr]'),
                        ('Paged', '8'),
                        ('Total', '8'),
                        ('Path', '46'),
                        ('Dump file', '46'),
                    ])
        else:
            return renderers.TreeGrid([
                        ('Pid', '4'),
                        ('Process', '12'),
                        ('Module Name', '20'),
                        ('Module Base', '[addr]'),
                        ('Paged', '8'),
                        ('Total', '8'),
                        ('Path', '46'),
                    ])

    def render_text(self, outfd, data):

        table_header = [('Pid', '4'),
                        ('Process', '12'),
                        ('Module Name', '20'),
                        ('Module Base', '[addr]'),
                        ('Paged', '8'),
                        ('Total', '8'),
                        ('Path', '46')]
        if self._config.DUMP_DIR:
            table_header = table_header + [('Dump file', '46')]
        self.table_header(outfd, table_header)
          
        if self._config.DUMP_DIR:
            for pid, process, module, address, paged_pages, total_pages, path, dump in data:
                self.table_row(outfd, pid, process, module, address, paged_pages, total_pages, path, dump)
        else: 
            for pid, process, module, address, paged_pages, total_pages, path, dump in data:
                self.table_row(outfd, pid, process, module, address, paged_pages, total_pages, path)

        





