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


    def calculate(self):
        self.addr_space = utils.load_as(self._config)
        if self._config.PID:
            pids = self._config.PID.split(',')

        for task in tasks.pslist(self.addr_space):
            if (not self._config.PID) or (str(task.UniqueProcessId) in pids):
                task_space = task.get_process_address_space()
                for mod in task.get_load_modules():
                    count_valid_pages = 0
                    dump_file = None
                    if self._config.DUMP_DIR:
                        if not os.path.exists(self._config.DUMP_DIR):
                            os.makedirs(self._config.DUMP_DIR)
                        # Create dump_file
                        dump_file = os.path.join(self._config.DUMP_DIR,'{0}-{1}-{2}.csv'.format(task.ImageFileName, task.UniqueProcessId, mod.BaseDllName.v()))
                        with open(dump_file, "w+") as f:
                            f.write("VADDR,\t\tPHYADDR\n")
                            for i in range(0, mod.SizeOfImage, PAGE_SIZE):
                                phyaddr = task_space.vtop(mod.DllBase+i)
                                if phyaddr:
                                    count_valid_pages += 1
                                    # Add line to dump_file
                                    f.write("{}\t{}\n".format(hex(mod.DllBase+i)[:-1],hex(phyaddr)[:-1]))

                        
                    else:
                        for i in range(0, mod.SizeOfImage, PAGE_SIZE):
                            if task_space.vtop(mod.DllBase+i):
                                count_valid_pages += 1

                    total_pages = mod.SizeOfImage / PAGE_SIZE
                    yield (task.UniqueProcessId, task.ImageFileName, mod.BaseDllName.v(), mod.DllBase.v(), total_pages - count_valid_pages, total_pages, mod.FullDllName.v(), dump_file )

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
