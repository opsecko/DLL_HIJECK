import fire
import logging
import os
from logpack import setup_logger,LOG
from emulation import emulation


def traversal_files(path):
    files = []
    for item in os.scandir(path):
        if item.is_file():
            files.append(item.path)
        else:
            traversal_files(item)
    return files

def do_it(
        path_to_check: str,
        dir_path:bool = False,
        verbose: bool = False,
         ):
    
    setup_logger(verbose)

    if dir_path:
        if os.path.isdir(path_to_check):
            pes = traversal_files(path_to_check)
            for peitem in pes:
                LOG.debug(f"check {peitem}")
                emu = emulation(peitem)
                emu.frida_exec()
        else:
            LOG.error(f"{path_to_check} is not dir path")
    else:
        if os.path.isfile(path_to_check):
            LOG.debug(f"check {path_to_check}")
            emu = emulation(path_to_check)
            emu.frida_exec()
        else:
            LOG.error(f"{path_to_check} is not file")
        
def main():
    fire.Fire(do_it)

if __name__ == '__main__':
    main()