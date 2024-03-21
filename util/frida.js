///<reference path='frida-gum.d.ts'/>
//https://bbs.kanxue.com/thread-254086.htm

let KnownDLLs = ["kernelbase.dll","kerlen32.dll","ntdll.dll","wow64cpu.dll","wowarmhw.dll","xtajit.dll","advapi32.dll","clbcatq.dll","combase.dll","comdlg32.dll","coml2.dll","difxapi.dll","gdi32.dll","gdiplus.dll","imagehlp.dll","imm32.dll","kernel32.dll","msctf.dll","msvcrt.dll","normaliz.dll","nsi.dll","ole32.dll","oleaut32.dll","psapi.dll","rpcrt4.dll","sechost.dll","setupapi.dll","shcore.dll","shell32.dll","shlwapi.dll","user32.dll","wldap32.dll","wow64.dll","wow64win.dll","ws2_32.dll",]

let currentDll = ""

function log(message){
    console.log(`frida-agen: ${message}`);
}

const fakeDllBase = 0x7FF133700000

function isVictimModule(modulePath) {
    let lowString = modulePath.toLowerCase()
    if (!lowString.endsWith(".dll")) {
        lowString += ".dll";
    }
    let inKnownDLLs = KnownDLLs.indexOf(lowString)
    let indexpoint = lowString.lastIndexOf('c:\\windows\\system32')
    if((inKnownDLLs != -1) || (indexpoint != -1)){
        return false
    }
    return true
}


var victimFunc = new NativeCallback(function () {
    send("[pwn]:dunamic find!!!!!!!!!!!!!!!!!!!")
}, 'void', []);

rpc.exports = {
    setHookStart:function(executeName){
        log(`start [${executeName}] run frida agent`)
        const fLoadLibraryW = Module.findExportByName('Kernel32', 'LoadLibraryW');
        Interceptor.attach(fLoadLibraryW, {
            onEnter: function (args) {
                let loadDllName = args[0].readUtf16String()
                this.moduleName= loadDllName
                let bisVictimmodule = isVictimModule(loadDllName)
                if (bisVictimmodule){
                    this.moduleisvictim= true
                }
                else{
                    this.moduleisvictim= false
                }
            },
            onLeave: function(retval){ 
                log(`onLeave: [${this.moduleName}] isvictimemodule: [${this.moduleisvictim}] dllmain called`)
                if (this.moduleisvictim == true){
                    send(`[pwn]:[${this.moduleName}] dllmain called!!!!!!!!!!!!!!!!!!!`)
                    //log(`replace [${retval}] to fakeDllBase address [${fakeDllBase.toString()}]`)
                    retval.replace(fakeDllBase)
                }
            }
        })

        const fGetCurrentProcess = Module.findExportByName('Kernel32', 'GetProcAddress');
        Interceptor.attach(fGetCurrentProcess, {
            onEnter: function (args) {
                if(args[0] == fakeDllBase){
                    let procName= args[1].readUtf8String()
                    log(`check [${procName}] is call?`)
                    this.isvictimFunc = true
                }
                else{
                    this.isvictimFunc = false
                }
                
            },
            onLeave: function(retval){ 
               if(this.isvictimFunc == true){
                retval.replace(victimFunc)
               }
            }
        })

        const fZwTerminateProcess = Module.findExportByName('ntdll', 'ZwTerminateProcess');
        Interceptor.attach(fZwTerminateProcess, {
            onEnter: function (args) {
                log("TerminateProcess")
            },
        })
    },

    setThirdDllHook:function(thirdDll){
    var module=Process.findModuleByName(thirdDll);


    var exports = module.enumerateExports();

    for(var i=0;i<exports.length;i++)
    {
        Interceptor.attach(exports[i].address, {
            onEnter: function (args) {
                var mod = Process.getModuleByAddress(this.context.rip)
                var exports2 = mod.enumerateExports();
                
                for(var j=0;j<exports2.length;j++)
                {
                    if(Number(exports2[j].address) == Number(this.context.rip))
                    {
                        send(`[pwn]:static find!!!!!!!!!!!!!!!!!!!").[${mod.name}:${exports2[j].name}]`);
                    }
                }
            }
        })
    }
    }

}
