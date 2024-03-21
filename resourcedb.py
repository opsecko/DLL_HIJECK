from importlib import resources

def GetFridajs()->str:
    with resources.open_text('util', 'frida.js') as f:
        content = f.read()
    return content

def GetTmpModule():
    with resources.open_binary('util', 'TmpModule_x64.dll') as f:
        content = f.read()
    return content