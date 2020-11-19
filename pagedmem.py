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


PAGE_SIZE = 4096

class PagedMem(AbstractWindowsCommand):
    """ XXX: List of valid pages """

    def __init__(self, config, *args, **kwargs):
        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option='D', help='Directory in which to dump files', action='store', type='str')
        self._config.add_option('PID', short_option='p', help='Process ID', action='store',type='str')
        self._config.add_option('LOGFILE', help='Logfile to dump full info', action='store',type='str')

    def write_to_file(self, filename, _list):
        
        with open(filename, "w+") as f:
            f.write("VADDR,PHYADDR\n")
            for vaddr, phyaddr in _list:
                f.write("{},{}\n".format(hex(vaddr), hex(pyhaddr)))   

    def calculate(self):
        self.addr_space = utils.load_as(self._config)
        if self._config.PID:
            pids = self._config.PID.split(',')

        # check logfile output
        log_file = None
        if self._config.LOGFILE:
            log_file = open(self._config.LOGFILE, "w+")

        # Modules on user space
        for task in tasks.pslist(self.addr_space):
            if (not self._config.PID) or (str(task.UniqueProcessId) in pids):
                task_space = task.get_process_address_space()
                for mod in task.get_load_modules():
                    count_valid_pages = 0
                    _list = []
                    for i in range(0, mod.SizeOfImage, PAGE_SIZE):
                        if task_space.is_valid_address(mod.DllBase + i):
                            count_valid_pages += 1
                            _list.append([mod.DllBase + i, task_space.vtop(mod.DllBase + i)])

                    dump_file = None
                    if self._config.DUMP_DIR:
                        if not os.path.exists(self._config.DUMP_DIR):
                            os.makedirs(self._config.DUMP_DIR)
                        # Create dump_file
                        dump_file = os.path.join(self._config.DUMP_DIR,'{0}-{1}-{2}.csv'.format(task.ImageFileName, task.UniqueProcessId, mod.BaseDllName.v()))
                        self.write_to_file(dump_file, _list)
                        
                    total_pages = mod.SizeOfImage / PAGE_SIZE
                    if log_file:
                        baseDllName = (mod.BaseDllName.v())
                        if type(baseDllName) == obj.NoneObject:
                            baseDllName = '-----'
                        fullDllName = mod.FullDllName.v()
                        if type(fullDllName) == obj.NoneObject:
                            fullDllName = '-----'
                        log_file.write('\t'.join((str(task.UniqueProcessId), str(task.ImageFileName), baseDllName, str(mod.DllBase.v()), str(total_pages - count_valid_pages), str(total_pages), fullDllName)) + '\n')
                    yield (task.UniqueProcessId, task.ImageFileName, mod.BaseDllName.v(), mod.DllBase.v(), total_pages - count_valid_pages, total_pages, mod.FullDllName.v(), dump_file )

        # Drivers -- part of this code is inspired in moddump plugin 
        mods = dict((mod.DllBase.v(), mod) for mod in modules.lsmod(self.addr_space))
        procs = list(tasks.pslist(self.addr_space))

        for mod in mods.values():
            mod_base = mod.DllBase.v()
            space = tasks.find_space(self.addr_space, procs, mod_base)
            count_valid_pages = 0
            _list = []
            if space != None: # check if we have retrieved the correct AS
            # when no retrieved, paged memory pages will be equal to the total pages
                for i in range(0, mod.SizeOfImage, PAGE_SIZE):
                    if space.is_valid_address(mod.DllBase + i):
                        count_valid_pages += 1
                    _list.append([mod.DllBase+i, space.vtop(mod.DllBase + i)])

            dump_file = None
            if self._config.DUMP_DIR:
                if not os.path.exists(self._config.DUMP_DIR):
                    os.makedirs(self._config.DUMP_DIR)
                # Create dump_file
                dump_file = os.path.join(self._config.DUMP_DIR,'drv_{}.csv'.format(mod.BaseDllName.v()))
                self.write_to_file(dump_file, _list)

            total_pages = mod.SizeOfImage / PAGE_SIZE
            if log_file:
                log_file.write('\t'.join((str(0), str(0), str(mod.BaseDllName.v()), str(mod.DllBase.v()), str(total_pages - count_valid_pages), str(total_pages), str(mod.FullDllName.v()))) + '\n')
            yield ('--', '--', mod.BaseDllName.v(), mod.DllBase.v(), total_pages - count_valid_pages, total_pages, mod.FullDllName.v(), dump_file )

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
