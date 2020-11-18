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

    
    def iterate_memspace(self, task):
        """ Iterates in the memory space of the given task, computing the valid pages """
        
        retdata = []
        task_space = task.get_process_address_space()
        for mod in task.get_load_modules():
            count_valid_pages = 0
                    
            # Create dump_file, if needed
            dump_file = None
            f = None
            if self._config.DUMP_DIR:
                dump_file = os.path.join(self._config.DUMP_DIR,'{0}-{1}-{2}.csv'.format(task.ImageFileName, task.UniqueProcessId, mod.BaseDllName.v()))
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
            retdata.append([task.UniqueProcessId, task.ImageFileName, mod.BaseDllName.v(), mod.DllBase.v(), count_valid_pages, total_pages, mod.FullDllName.v(), dump_file if dump_file else None])
        return retdata

    def calculate(self):
        """ TODO """

        self.addr_space = utils.load_as(self._config)
        if self._config.PID:
            pids = self._config.PID.split(',')

        # iterate on tasks
        tasks_info = []
        for task in tasks.pslist(self.addr_space):
            if (not self._config.PID) or (str(task.UniqueProcessId) in pids):
                tasks_info.extend(self.iterate_memspace(task))

        return tasks_info

    def unified_output(self, data):
        if self._config.DUMP_DIR:
            return renderers.TreeGrid([
                        ('Pid', '4'),
                        ('Process', '25'),
                        ('Module Name', '33'),
                        ('Module Base', '[addr]'),
                        ('Num paged', '12'),
                        ('Num resident', '12'),
                        ('Path', '46'),
                        ('Dump file', '46'),
                    ])
        else:
            return renderers.TreeGrid([
                        ('Pid', '4'),
                        ('Process', '25'),
                        ('Module Name', '33'),
                        ('Module Base', '[addr]'),
                        ('Num paged', '12'),
                        ('Num resident', '12'),
                        ('Path', '46'),
                    ])

    def render_text(self, outfd, data):

        table_header = [('Pid', '4'),
                        ('Process', '8'),
                        ('Module Name', '8'),
                        ('Module Base', '[addr]'),
                        ('Paged', '5'),
                        ('Total', '5'),
                        ('Path', '46')]
        if self._config.DUMP_DIR:
            table_header = table_header + [('Dump file', '46')]
        self.table_header(outfd, table_header)
          
        if self._config.DUMP_DIR:
            for pid, process, module, address, valid_pages, total_pages, path, dump in data:
                self.table_row(outfd, pid, process, module, address, valid_pages, total_pages, path, dump)
        else: 
            for pid, process, module, address, valid_pages, total_pages, path, dump in data:
                self.table_row(outfd, pid, process, module, address, valid_pages, total_pages, path)

        




    '''class PagedMemPrint(object):
    def __init__(self, pid, process, module, address, valid_pages, total_pages, path, dump_file=None):
        self.pid = pid
        self.process = process
        self.module = module
        self.address = address
        self.valid_pages = valid_pages
        self.total_pages = total_pages
        self.path = path
        self.dump_file = dump_file

    def get_generator(self):
        if self._config.DUMP_DIR:
            return [
                int(self.pid),
                str(self.process),
                str(self.mod_name),
                Address(self.mod_base),
                int(self.count_valid_pages),
                int(self.total_pages),
                str(self.path),
                str(self.dump_file)
            ]
        else:
            return [
                int(self.pid),
                str(self.process),
                str(self.mod_name),
                Address(self.mod_base),
                int(self.count_valid_pages),
                int(self.total_pages),
                str(self.path)
            ]'''
