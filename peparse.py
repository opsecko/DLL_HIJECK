import pefile
from logpack import LOG

class peparse:
    def __init__(self,
                 path,
                 mem=False) -> None:
        if mem:
            self.binary = pefile.PE(data=path) 
        else:
            self.binary = pefile.PE(path) 

    def get_import_table(self):
        if hasattr(self.binary, 'DIRECTORY_ENTRY_IMPORT'):
            return self.binary.DIRECTORY_ENTRY_IMPORT
        return None
    
    def get_machine_arch(self):
        return  self.binary.FILE_HEADER.Machine
    
    def set_export_as_list(self,export_list):
        for i in range(len(export_list)):
            self.binary.DIRECTORY_ENTRY_EXPORT.symbols[i].name = export_list[i].name+ b'\0'

        # for index, value in enumerate(self.binary.DIRECTORY_ENTRY_EXPORT.symbols):
        #     value.name = export_list[index].name
    def save_to_desk(self,path):
        self.binary.write(path)
        self.binary.close() 