import pefile
import frida
import time,os,signal,shutil
import resourcedb
from peparse import peparse
from logpack import LOG

def on_message(message, data):
    LOG.info(f"on_message : {message}")

class emulation:
    def __init__(self,
                 pe_path,
                 exec_dir="exec") -> None:
       
        script_path = os.path.dirname(os.path.abspath(__file__))
        self.exec_dir = os.path.join(script_path, exec_dir)
        if not os.path.exists(self.exec_dir):
            os.makedirs(self.exec_dir) 
        
        self.pe_path = os.path.join(self.exec_dir, os.path.basename(pe_path))
        shutil.copy(pe_path, self.pe_path)
        self.thrid_dll = []
        self.peobj = peparse(pe_path)

    def construct_test_dll(self,dllname,imports):
        test_dll = peparse(resourcedb.GetTmpModule(),True)
        test_dll.set_export_as_list(imports)
        test_dll.save_to_desk(os.path.join(self.exec_dir,dllname))



    def parse_thrid_dll(self):
        system_module_dir = [R"C:\Windows\System32"]
        imports = self.peobj.get_import_table()
        self.thrid_dll = []
        for imported_library in imports:
            is_system_module = False
            for item in system_module_dir:
                if os.path.exists(os.path.join(item,imported_library.dll.decode())):
                    is_system_module = True
                    break
 
            if is_system_module:
                continue

            self.construct_test_dll(imported_library.dll.decode(),imported_library.imports)
            self.thrid_dll.append(imported_library.dll.decode())
    def clear_exec_dir(self):
        for i in self.thrid_dll:
            os.remove(os.path.join(self.exec_dir,i))
        os.remove(self.pe_path)

    def frida_exec(self):
        try:
            if self.peobj.get_machine_arch() != pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                LOG.error("{} is not support plat".format(self.pe_path))
                return 
            self.parse_thrid_dll()
            pid = frida.spawn(self.pe_path)
            LOG.debug('current process is {}'.format(pid))
            session = frida.attach(pid)
            script = session.create_script(resourcedb.GetFridajs())
            
            script.on('message', on_message)
            script.load()
            frida_rpc = script.exports_sync
            frida_rpc.set_hook_start(self.pe_path)
            if len(self.thrid_dll) != 0:
                for item in self.thrid_dll:
                    frida_rpc.set_third_dll_hook(item)
            frida.resume(pid)

            # wait 1 sec kill process
            time.sleep(1)
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
            except OSError:
                print("Process has exited")
            
            self.clear_exec_dir()
        except Exception as e:
            LOG.error("{} fail as: {}".format(self.pe_path,e))
