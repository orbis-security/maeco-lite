import json
import urllib
import random
import re

from owlready2 import *

api_actions = {}
file_regex_patterns = {}
registry_regex_patterns = {}

def load_actions(path):
    global api_actions 

    try:
        with open(path) as file:
            api_actions = json.loads(file.read())
    except OSError:
        print("[*] Failed to open file: ", path)

def load_file_regex(path):
    global file_regex_patterns
    
    try:
        with open(path) as file:
            file_regex_patterns = json.loads(file.read())
    except OSError:
        print("[*] Failed to open file: ", path)

def load_registry_regex(path):
    global registry_regex_patterns
    
    try:
        with open(path) as file:
            registry_regex_patterns = json.loads(file.read())
    except OSError:
        print("[*] Failed to open file: ", path)

def has_api_action(api_calls, action):
    for api_call in api_calls:
        name = api_call['name']
        for ac in api_actions[action]:
            f = name.lower()
            if f.find(ac) != -1:
                return True
    return False

def map_files(process, process_name, path, ot, uid):
    file_path = path + "/processes/" + process_name + "." + uid + "/files.json"

    try:
        with open(file_path) as file:
            files = json.load(file)
    except OSError:
        print("[*] Failed to open file: ", file_path)
        return

    for file_op in files:
        op_type = file_op.get('type', '')
        file_path_str = file_op.get('path', '')
        access = file_op.get('access', '')
        
        file_class = None
        for class_name, patterns in file_regex_patterns.items():
            for pattern in patterns:
                if re.search(pattern, file_path_str):
                    file_class = class_name
                    break
            if file_class:
                break
        
        if file_class:
            file_obj_name = file_path_str.replace('\\', '_').replace('/', '_').replace(':', '_').replace('%', '_')
            file_obj = getattr(ot, file_class)(file_obj_name)
        else:
            continue
        
        if op_type == 'CREATE':
            if not hasattr(process, 'createdFile'):
                process.createdFile = []
            process.createdFile.append(file_obj)
        elif op_type == 'OPEN':
            if not hasattr(process, 'openedFile'):
                process.openedFile = []
            process.openedFile.append(file_obj)
        elif op_type == 'WRITE':
            if not hasattr(process, 'writtenToFile'):
                process.writtenToFile = []
            process.writtenToFile.append(file_obj)

def map_registry(process, process_name, path, ot, uid):
    registry_path = path + "/processes/" + process_name + "." + uid + "/registry.json"
    
    try:
        with open(registry_path) as file:
            registry_ops = json.load(file)
    except (OSError, FileNotFoundError):
        return

    for reg_op in registry_ops:
        op_name = reg_op.get('name', '')
        parameters = reg_op.get('parameters', {})
        reg_key_path = parameters.get('Path', '')
        
        if not reg_key_path:
            continue
        
        reg_key_class = None
        for class_name, patterns in registry_regex_patterns.items():
            for pattern in patterns:
                if re.search(pattern, reg_key_path):
                    reg_key_class = class_name
                    break
            if reg_key_class:
                break
        
        reg_key_obj_name = reg_key_path.replace('\\', '_').replace('/', '_').replace(':', '_').replace(' ', '_')
        if reg_key_class:
            reg_key_obj = getattr(ot, reg_key_class)(reg_key_obj_name)
        else:
            continue
        
        if op_name == 'Create':
            if not hasattr(process, 'createdRegistryKey'):
                process.createdRegistryKey = []
            process.createdRegistryKey.append(reg_key_obj)
        elif op_name == 'Delete':
            if not hasattr(process, 'deletedRegistryKey'):
                process.deletedRegistryKey = []
            process.deletedRegistryKey.append(reg_key_obj)
        elif op_name == 'Open':
            if not hasattr(process, 'openedRegistryKey'):
                process.openedRegistryKey = []
            process.openedRegistryKey.append(reg_key_obj)
        elif op_name == 'Query':
            if not hasattr(process, 'queriedRegistryKey'):
                process.queriedRegistryKey = []
            process.queriedRegistryKey.append(reg_key_obj)
        elif op_name == 'Write':
            if not hasattr(process, 'writtenToRegistryKey'):
                process.writtenToRegistryKey = []
            process.writtenToRegistryKey.append(reg_key_obj)

def map_actions(process, process_name, path, ot, uid):
    api_call_path = path + "/processes/" + process_name + "." + uid + "/api_calls.json"
    with open(api_call_path) as file:
        api_calls = json.load(file)
    
    actions = []

     # ACCESS MANAGEMENT
    if has_api_action(api_calls, "add-user"):
        actions.append(ot.AddUser("add-user"))
    if has_api_action(api_calls, "change-password"):
        actions.append(ot.ChangePassword("change-password"))
    if has_api_action(api_calls, "delete-user"):
        actions.append(ot.DeleteUser("delete-user"))
    if has_api_action(api_calls, "enumerate-users"):
        actions.append(ot.EnumerateUsers("enumerate-users"))
    if has_api_action(api_calls, "get-username"):
        actions.append(ot.GetUsername("get-username"))
    if has_api_action(api_calls, "logon-as-user"):
        actions.append(ot.LogonAsUser("logon-as-user"))
    if has_api_action(api_calls, "remove-user-from-group"):
        actions.append(ot.RemoveUserFromGroup("remove-user-from-group"))

    # ANTI DEBUGGING
    if has_api_action(api_calls, "check-for-kernel-debugger"):
        actions.append(ot.CheckForKernelDebugger("check-for-kernel-debugger"))
    if has_api_action(api_calls, "check-for-remote-debugger"):
        actions.append(ot.CheckForRemoteDebugger("check-for-remote-debugger"))
    if has_api_action(api_calls, "output-debug-string"):
        actions.append(ot.OutputDebugString("output-debug-string"))

    # CRYPTOGRAPHY
    if has_api_action(api_calls, "encrypt"):
        actions.append(ot.Encrypt("encrypt"))
    if has_api_action(api_calls, "decrypt"):
        actions.append(ot.Decrypt("decrypt"))
    if has_api_action(api_calls, "generate-key"):
        actions.append(ot.GenerateKey("generate-key"))
    if has_api_action(api_calls, "hash"):
        actions.append(ot.Hash("hash"))

    # DIRECTORY HANDLING
    if has_api_action(api_calls, "delete-directory"):
        actions.append(ot.DeleteDirectory("delete-directory"))
    if has_api_action(api_calls, "monitor-directory"):
        actions.append(ot.MonitorDirectory("monitor-directory"))
    if has_api_action(api_calls, "open-directory"):
        actions.append(ot.OpenDirectory("open-directory"))
    if has_api_action(api_calls, "create-directory"):
        actions.append(ot.CreateDirectory("create-directory"))

    # DISK MANAGEMENT
    if has_api_action(api_calls, "enumerate-disks"):
        actions.append(ot.EnumerateDisks("enumerate-disks"))
    if has_api_action(api_calls, "get-disk-attributes"):
        actions.append(ot.GetDiskAttributes("get-disk-attributes"))
    if has_api_action(api_calls, "get-disk-type"):
        actions.append(ot.GetDiskType("get-disk-type"))
    if has_api_action(api_calls, "mount-disk"):
        actions.append(ot.MountDisk("mount-disk"))
    if has_api_action(api_calls, "unmount-disk"):
        actions.append(ot.UnmountDisk("unmount-disk"))

    # FILE HANDLING
    if has_api_action(api_calls, "close-file"):
        actions.append(ot.CloseFile("close-file"))
    if has_api_action(api_calls, "copy-file"):
        actions.append(ot.CopyFile("copy-file"))
    if has_api_action(api_calls, "create-file"):
        actions.append(ot.CreateFile("create-file"))
    if has_api_action(api_calls, "create-file-mapping"):
        actions.append(ot.CreateFileMapping("create-file-mapping"))
    if has_api_action(api_calls, "create-file-symbolic-link"):
        actions.append(ot.CreateFileSymbolicLink("create-file-symbolic-link"))
    if has_api_action(api_calls, "delete-file"):
        actions.append(ot.DeleteFile("delete-file"))
    if has_api_action(api_calls, "download-file"):
        actions.append(ot.DownloadFile("download-file"))
    if has_api_action(api_calls, "execute-file"):
        actions.append(ot.ExecuteFile("execute-file"))
    if has_api_action(api_calls, "find-file"):
        actions.append(ot.FindFile("find-file"))
    if has_api_action(api_calls, "get-file-or-directory-attributes"):
        actions.append(ot.GetFileOrDirectoryAttributes("get-file-or-directory-attributes"))
    if has_api_action(api_calls, "get-temporary-files-directory"):
        actions.append(ot.GetTemporaryFilesDirectory("get-temporary-files-directory"))
    if has_api_action(api_calls, "lock-file"):
        actions.append(ot.LockFile("lock-file"))
    if has_api_action(api_calls, "map-file-into-process"):
        actions.append(ot.MapFileIntoProcess("map-file-into-process"))
    if has_api_action(api_calls, "move-file"):
        actions.append(ot.MoveFile("move-file"))
    if has_api_action(api_calls, "open-file-mapping"):
        actions.append(ot.OpenFileMapping("open-file-mapping"))
    if has_api_action(api_calls, "read-from-file"):
        actions.append(ot.ReadFromFile("read-from-file"))
    if has_api_action(api_calls, "set-file-or-directory-attributes"):
        actions.append(ot.SetFileOrDirectoryAttributes("set-file-or-directory-attributes"))
    if has_api_action(api_calls, "unlock-file"):
        actions.append(ot.UnlockFile("unlock-file"))
    if has_api_action(api_calls, "unmap-file-from-process"):
        actions.append(ot.UnmapFileFromProcess("unmap-file-from-process"))
    if has_api_action(api_calls, "write-to-file"):
        actions.append(ot.WriteToFile("write-to-file"))

    # INTER PROCESS COMMUNICATION
    if has_api_action(api_calls, "connect-to-named-pipe"):
        actions.append(ot.ConnectToNamedPipe("connect-to-named-pipe"))
    if has_api_action(api_calls, "create-mailslot"):
        actions.append(ot.CreateMailSlot("create-mailslot"))
    if has_api_action(api_calls, "create-named-pipe"):
        actions.append(ot.CreateNamedPipe("create-named-pipe"))
    
    # LIBRARY HANDLING
    if has_api_action(api_calls, "enumerate-libraries"):
        actions.append(ot.EnumerateLibraries("enumerate-libraries"))
    if has_api_action(api_calls, "free-library"):
        actions.append(ot.FreeLibrary("free-library"))
    if has_api_action(api_calls, "get-function-address"):
        actions.append(ot.GetFunctionAddress("get-function-address"))
    if has_api_action(api_calls, "load-library"):
        actions.append(ot.LoadLibrary("load-library"))

    # NETWORKING
    if has_api_action(api_calls, "accept-socket-connection"):
        actions.append(ot.AcceptSocketConnection("accept-socket-connection"))
    if has_api_action(api_calls, "bind-address-to-socket"):
        actions.append(ot.BindAddressToSocket("bind-address-to-socket"))
    if has_api_action(api_calls, "close-socket"):
        actions.append(ot.CloseSocket("close-socket"))
    if has_api_action(api_calls, "connect-to-ftp-server"):
        actions.append(ot.ConnectToFtpServer("connect-to-ftp-server"))
    if has_api_action(api_calls, "connect-to-socket"):
        actions.append(ot.ConnectToSocket("connect-to-socket"))
    if has_api_action(api_calls, "connect-to-url"):
        actions.append(ot.ConnectToUrl("connect-to-url"))
    if has_api_action(api_calls, "create-socket"):
        actions.append(ot.CreateSocket("create-socket"))
    if has_api_action(api_calls, "get-host-by-address"):
        actions.append(ot.GetHostByAddress("get-host-by-address"))
    if has_api_action(api_calls, "get-host-by-name"):
        actions.append(ot.GetHostByName("get-get-host-by-name"))
    if has_api_action(api_calls, "listen-on-socket"):
        actions.append(ot.ListenOnSocket("listen-on-socket"))
    if has_api_action(api_calls, "send-data-on-socket"):
        actions.append(ot.SendDataOnSocket("send-data-on-socket"))
    if has_api_action(api_calls, "send-dns-query"):
        actions.append(ot.SendDnsQuery("send-dns-query"))
    if has_api_action(api_calls, "send-http-connect-request"):
        actions.append(ot.SendHttpConnectRequest("send-http-connect-request"))
    if has_api_action(api_calls, "send-icmp-request"):
        actions.append(ot.SendIcmpRequest("send-icmp-request"))
    if has_api_action(api_calls, "receive-data-on-socket"):
        actions.append(ot.ReceiveDataOnSocket("receive-data-on-socket"))
    if has_api_action(api_calls, "send-http-request"):
        actions.append(ot.SendHttpRequest("send-http-request"))
    if has_api_action(api_calls, "send-ftp-command"):
        actions.append(ot.SendFtpCommand("send-ftp-command"))

    # PROCESS HANDLING
    if has_api_action(api_calls, "allocate-process-virtual-memory"):
        actions.append(ot.AllocateProcessVirtualMemory("allocate-process-virtual-memory"))
    if has_api_action(api_calls, "create-process"):
        actions.append(ot.CreateProcess("create-process"))
    if has_api_action(api_calls, "impersonate-process"):
        actions.append(ot.ImpersonateProcess("impersonate-process"))
    if has_api_action(api_calls, "create-process-as-user"):
        actions.append(ot.CreateProcessAsUser("create-process-as-user"))
    if has_api_action(api_calls, "enumerate-processes"):
        actions.append(ot.EnumerateProcesses("enumerate-processes"))
    if has_api_action(api_calls, "flush-process-instruction-cache"):
        actions.append(ot.FlushProcessInstructionCache("flush-process-instruction-cache"))
    if has_api_action(api_calls, "free-process-virtual-memory"):
        actions.append(ot.FreeProcessVirtualMemory("free-process-virtual-memory"))
    if has_api_action(api_calls, "get-process-current-directory"):
        actions.append(ot.GetProcessCurrentDirectory("get-process-current-directory"))
    if has_api_action(api_calls, "get-process-environment-variable"):
        actions.append(ot.GetProcessEnvironmentVariable("get-process-environment-variable"))
    if has_api_action(api_calls, "get-process-startupinfo"):
        actions.append(ot.GetProcessStartupinfo("get-process-startupinfo"))
    if has_api_action(api_calls, "kill-process"):
        actions.append(ot.KillProcess("kill-process"))
    if has_api_action(api_calls, "modify-process-virtual-memory-protection"):
        actions.append(ot.ModifyProcessVirtualMemoryProtection("modify-process-virtual-memory-protection"))
    if has_api_action(api_calls, "open-process"):
        actions.append(ot.OpenProcess("open-process"))
    if has_api_action(api_calls, "read-from-process-memory"):
        actions.append(ot.ReadFromProcessMemory("read-from-process-memory"))
    if has_api_action(api_calls, "set-process-current-directory"):
        actions.append(ot.SetProcessCurrentDirectory("set-process-current-directory"))
    if has_api_action(api_calls, "set-process-environment-variable"):
        actions.append(ot.SetProcessEnvironmentVariable("set-process-environment-variable"))
    if has_api_action(api_calls, "sleep-process"):
        actions.append(ot.SleepProcess("sleep-process"))
    if has_api_action(api_calls, "write-to-process-memory"):
        actions.append(ot.WriteToProcessMemory("write-to-process-memory"))

    # REGISTRY HANDLING
    if has_api_action(api_calls, "close-registry-key"):
        actions.append(ot.CloseRegistryKey("close-registry-key"))
    if has_api_action(api_calls, "create-registry-key"):
        actions.append(ot.CreateRegistryKey("create-registry-key"))
    if has_api_action(api_calls, "create-registry-key-value"):
        actions.append(ot.CreateRegistryKeyValue("create-registry-key-value"))
    if has_api_action(api_calls, "delete-registry-key-value"):
        actions.append(ot.DeleteRegistryKeyValue("delete-registry-key-value"))
    if has_api_action(api_calls, "delete-registry-key"):
        actions.append(ot.DeleteRegistryKey("delete-registry-key"))
    if has_api_action(api_calls, "enumerate-registry-key-subkeys"):
        actions.append(ot.EnumerateRegistryKeySubkeys("enumerate-registry-key-subkeys"))
    if has_api_action(api_calls, "enumerate-registry-key-values"):
        actions.append(ot.EnumerateRegistryKeyValues("enumerate-registry-key-values"))
    if has_api_action(api_calls, "modify-registry-key"):
        actions.append(ot.ModifyRegistryKey("modify-registry-key"))
    if has_api_action(api_calls, "monitor-registry-key"):
        actions.append(ot.MonitorRegistryKey("monitor-registry-key"))
    if has_api_action(api_calls, "open-registry-key"):
        actions.append(ot.OpenRegistryKey("open-registry-key"))
    if has_api_action(api_calls, "read-registry-key-value"):
        actions.append(ot.ReadRegistryKeyValue("read-registry-key-value"))

    # RESOURCE SHARING
    if has_api_action(api_calls, "add-network-share"):
        actions.append(ot.AddNetworkShare("add-network-share"))
    if has_api_action(api_calls, "delete-network-share"):
        actions.append(ot.DeleteNetworkShare("delete-network-share"))
    if has_api_action(api_calls, "enumerate-network-shares"):
        actions.append(ot.EnumerateNetworkShares("enumerate-network-shares"))

    # SERVICE HANDLING
    if has_api_action(api_calls, "create-service"):
        actions.append(ot.CreateService("create-service"))
    if has_api_action(api_calls, "delete-service"):
        actions.append(ot.DeleteService("delete-service"))
    if has_api_action(api_calls, "enumerate-services"):
        actions.append(ot.EnumerateServices("enumerate-services"))
    if has_api_action(api_calls, "modify-service-configuration"):
        actions.append(ot.ModifyServiceConfiguration("modify-service-configuration"))
    if has_api_action(api_calls, "open-service"):
        actions.append(ot.OpenService("open-service"))
    if has_api_action(api_calls, "start-service"):
        actions.append(ot.StartService("start-service"))
    if has_api_action(api_calls, "stop-service"):
        actions.append(ot.StopService("stop-service"))

    # SYNCHRONIZATION PRIMITIVES HANDLING
    if has_api_action(api_calls, "create-critical-section"):
        actions.append(ot.CreateCriticalSection("create-critical-section"))
    if has_api_action(api_calls, "create-event"):
        actions.append(ot.CreateEvent("create-event"))
    if has_api_action(api_calls, "create-mutex"):
        actions.append(ot.CreateMutex("create-mutex"))
    if has_api_action(api_calls, "create-semaphore"):
        actions.append(ot.CreateSemaphore("create-semaphore"))
    if has_api_action(api_calls, "delete-critical-section"):
        actions.append(ot.DeleteCriticalSection("delete-critical-section"))
    if has_api_action(api_calls, "open-critical-section"):
        actions.append(ot.OpenCriticalSection("open-critical-section"))
    if has_api_action(api_calls, "open-event"):
        actions.append(ot.OpenEvent("open-event"))
    if has_api_action(api_calls, "open-mutex"):
        actions.append(ot.OpenMutex("open-mutex"))
    if has_api_action(api_calls, "open-semaphore"):
        actions.append(ot.OpenSemaphore("open-semaphore"))
    if has_api_action(api_calls, "release-critical-section"):
        actions.append(ot.ReleaseCriticalSection("release-critical-section"))
    if has_api_action(api_calls, "release-mutex"):
        actions.append(ot.ReleaseMutex("release-mutex"))
    if has_api_action(api_calls, "release-semaphore"):
        actions.append(ot.ReleaseSemaphore("release-semaphore"))
    if has_api_action(api_calls, "reset-event"):
        actions.append(ot.ResetEvent("reset-event"))

    # SYSTEM MANIPULATION
    if has_api_action(api_calls, "add-scheduled-task"):
        actions.append(ot.AddScheduledTask("add-scheduled-task"))
    if has_api_action(api_calls, "get-elapsed-system-up-time"):
        actions.append(ot.GetElapsedSystemUpTime("get-elapsed-system-up-time"))
    if has_api_action(api_calls, "get-netbios-name"):
        actions.append(ot.GetNetbiosName("get-netbios-name"))
    if has_api_action(api_calls, "get-system-global-flags"):
        actions.append(ot.GetSystemGlobalFlags("get-system-global-flags"))
    if has_api_action(api_calls, "get-system-time"):
        actions.append(ot.GetSystemTime("get-system-time"))
    if has_api_action(api_calls, "get-windows-directory"):
        actions.append(ot.GetWindowsDirectory("get-windows-directory"))
    if has_api_action(api_calls, "get-windows-system-directory"):
        actions.append(ot.GetWindowsSystemDirectory("get-windows-system-directory"))
    if has_api_action(api_calls, "set-netbios-name"):
        actions.append(ot.SetNetbiosName("set-netbios-name"))
    if has_api_action(api_calls, "set-system-time"):
        actions.append(ot.SetSystemTime("set-system-time"))
    if has_api_action(api_calls, "shutdown-system"):
        actions.append(ot.ShutdownSystem("shutdown-system"))
    if has_api_action(api_calls, "unload-driver"):
        actions.append(ot.UnloadDriver("unload-driver"))
    if has_api_action(api_calls, "get-system-local-time"):
        actions.append(ot.GetSystemLocalTime("get-system-local-time"))

    # THREAD HANDLING
    if has_api_action(api_calls, "create-remote-thread-in-process"):
        actions.append(ot.CreateRemot.ThreadInProcess("create-remote-thread-in-process"))
    if has_api_action(api_calls, "create-thread"):
        actions.append(ot.CreateThread("create-thread"))
    if has_api_action(api_calls, "enumerate-threads"):
        actions.append(ot.EnumerateThreads("enumerate-threads"))
    if has_api_action(api_calls, "get-thread-context"):
        actions.append(ot.GetThreadContext("get-thread-context"))
    if has_api_action(api_calls, "kill-thread"):
        actions.append(ot.KillThread("kill-thread"))
    if has_api_action(api_calls, "queue-apc-in-thread"):
        actions.append(ot.QueueApcInThread("queue-apc-in-thread"))
    if has_api_action(api_calls, "revert-thread-to-self"):
        actions.append(ot.RevertThreadToSelf("revert-thread-to-self"))
    if has_api_action(api_calls, "set-thread-context"):
        actions.append(ot.SetThreadContext("set-thread-context"))

    # WINDOW HANDLING
    if has_api_action(api_calls, "add-windows-hook"):
        actions.append(ot.AddWindowsHook("add-windows-hook"))
    if has_api_action(api_calls, "create-dialog-box"):
        actions.append(ot.CreateDialogBox("create-dialog-box"))
    if has_api_action(api_calls, "create-window"):
        actions.append(ot.CreateWindow("create-window"))
    if has_api_action(api_calls, "enumerate-windows"):
        actions.append(ot.EnumerateWindows("enumerate-windows"))
    if has_api_action(api_calls, "find-window"):
         actions.append(ot.FindWindow("find-window"))
    if has_api_action(api_calls, "kill-window"):
        actions.append(ot.KillWindow("kill-window"))
    if has_api_action(api_calls, "show-window"):
        actions.append(ot.ShowWindow("show-window"))
    
    process.performedAction = actions
    
def map_mitre(sample, ot, sample_obj):
    techniques = []

    for technique in sample["mitre_attcks"]:
        # EXECUTION
        if technique['tactic'] == 'Execution':
            if technique["technique"] == "Native API":
                techniques.append(ot.NativeAPI("native-api"))
            if technique['technique'] == "Shared Modules":
                techniques.append(ot.SharedModules("shared-modules"))
            if technique['technique'] == "Scripting":
                techniques.append(ot.Scripting("scripting"))
            if technique['technique'] == "Command and Scripting Interpreter":
                techniques.append(ot.CommandAndScriptingInterpreter("command-and-scripting-interpreter"))
            if technique['technique'] == "Scheduled Task":
                techniques.append(ot.ScheduledTask("scheduled-task"))
            if technique['technique'] == "User Execution":
                techniques.append(ot.UserExecution("user-execution"))
            if technique['technique'] == "Inter-Process Communication":
                techniques.append(ot.ExecutionViaInterProcessCommunication("execution-via-inter-process-communication"))
            if technique['technique'] == "PowerShell":
                techniques.append(ot.PowerShell("powershell"))
            if technique['technique'] == "Windows Management Instrumentation":
                techniques.append(ot.WindowsManagementInstrumentation("windows-management-instrumentation"))
            if technique['technique'] == "Service Execution":
                techniques.append(ot.ServiceExecution("service-execution"))
            if technique['technique'] == "Local Job Scheduling":
                techniques.append(ot.LocalJobScheduling("local-job-scheduling"))
            if technique['technique'] == "Malicious File":
                techniques.append(ot.MaliciousFile("malicious-file"))
            if technique['technique'] == "Component Object Model":
                techniques.append(ot.ComponentObjectModel("component-object-model"))
            if technique['technique'] == "Dynamic Data Exchange":
                techniques.append(ot.DynamicDataExchange("dynamic-data-exchange"))
            if technique['technique'] == "JavaScript":
                techniques.append(ot.JavaScript("javascript"))
            if technique['technique'] == "Rundll32":
                techniques.append(ot.Rundll32("rundll32"))
            if technique['technique'] == "Software Deployment Tools":
                techniques.append(ot.SoftwareDeploymentTools("software-deployment-tools"))
            if technique['technique'] == "Exploitation for Client Execution":
                techniques.append(ot.ExploitationForClientExecution("exploitation-for-client-execution"))
            if technique['technique'] == "Visual Basic":
                techniques.append(ot.VisualBasic("visual-basic"))
            if technique['technique'] == "Python":
                techniques.append(ot.Python("python"))
            if technique['technique'] == "Windows Command Shell":
                techniques.append(ot.WindowsCommandShell("windows-command-shell"))
            if technique['technique'] == "Cron":
                techniques.append(ot.Cron("cron"))
            if technique['technique'] == "Systemd Timers":
                techniques.append(ot.SystemdTimers("systemd-timers"))
            if technique['technique'] == "Container Orchestration Job":
                techniques.append(ot.ContainerOrchestrationJob("container-orchestration-job"))
            if technique['technique'] == "AppleScript":
                techniques.append(ot.AppleScript("applescript"))
            if technique['technique'] == "Unix Shell":
                techniques.append(ot.UnixShell("unix-shell"))
            if technique['technique'] == "Network Device CLI":
                techniques.append(ot.NetworkDeviceCLI("network-device-cli"))
            if technique['technique'] == "Cloud API":
                techniques.append(ot.CloudAPI("cloud-api"))
            if technique['technique'] == "AutoHotKey & AutoIT":
                techniques.append(ot.AutoHotKeyAutoIT("autohotkey-autoit"))
            if technique['technique'] == "Lua":
                techniques.append(ot.Lua("lua"))
            if technique['technique'] == "Hypervisor CLI":
                techniques.append(ot.HypervisorCLI("hypervisor-cli"))
            if technique['technique'] == "Container CLI/API":
                techniques.append(ot.ContainerCLIAPI("container-cli-api"))
            if technique['technique'] == "Malicious Link":
                techniques.append(ot.MaliciousLink("malicious-link"))
            if technique['technique'] == "Malicious Image":
                techniques.append(ot.MaliciousImage("malicious-image"))
            if technique['technique'] == "Malicious Copy and Paste":
                techniques.append(ot.MaliciousCopyAndPaste("malicious-copy-and-paste"))
            if technique['technique'] == "Malicious Library":
                techniques.append(ot.MaliciousLibrary("malicious-library"))
            if technique['technique'] == "XPC Services":
                techniques.append(ot.XPCServices("xpc-services"))
            if technique['technique'] == "System Services":
                techniques.append(ot.SystemServices("system-services"))
            if technique['technique'] == "Launchctl":
                techniques.append(ot.Launchctl("launchctl"))
            if technique['technique'] == "Deploy Container":
                techniques.append(ot.DeployContainer("deploy-container"))
            if technique['technique'] == "Container Administration Command":
                techniques.append(ot.ContainerAdministrationCommand("container-administration-command"))
            if technique['technique'] == "Serverless Execution":
                techniques.append(ot.ServerlessExecution("serverless-execution"))
            if technique['technique'] == "Cloud Administration Command":
                techniques.append(ot.CloudAdministrationCommand("cloud-administration-command"))
            if technique['technique'] == "Input Injection":
                techniques.append(ot.InputInjection("input-injection"))
        
        # PERSISTENCE
        if technique['tactic'] == 'Persistence':
            if technique['technique'] == "Registry Run Keys / Startup Folder":
                techniques.append(ot.RegistryRunKeysStartupFolder("registry-run-keys-startup-folder"))
            if technique['technique'] == "Create or Modify System Process":
                techniques.append(ot.CreateOrModifySystemProcess("create-or-modify-system-process"))
            if technique['technique'] == "Boot or Logon Autostart Execution":
                techniques.append(ot.BootOrLogonAutostartExecution("boot-or-logon-autostart-execution"))
            if technique['technique'] == "DLL Side-Loading":
                techniques.append(ot.DLLSideLoading("dll-side-loading"))
            if technique['technique'] == "Shortcut Modification":
                techniques.append(ot.ShortcutModification("shortcut-modification"))
            if technique['technique'] == "File System Permissions Weakness":
                techniques.append(ot.FileSystemPermissionsWeakness("file-system-permissions-weakness"))
            if technique['technique'] == "Modify Registry":
                techniques.append(ot.ModifyRegistry("modify-registry"))
            if technique['technique'] == "Account Manipulation":
                techniques.append(ot.AccountManipulation("account-manipulation"))
            if technique['technique'] == "Windows Service":
                techniques.append(ot.WindowsService("windows-service"))
            if technique['technique'] == "Component Object Model Hijacking":
                techniques.append(ot.ComponentObjectModelHijacking("component-object-model-hijacking"))
            if technique['technique'] == "Kernel Modules and Extensions":
                techniques.append(ot.KernelModulesAndExtensions("kernel-modules-and-extensions"))
            if technique['technique'] == "Hooking":
                techniques.append(ot.Hooking("hooking"))
            if technique['technique'] == "DLL Search Order Hijacking":
                techniques.append(ot.DLLSearchOrderHijacking("dll-search-order-hijacking"))
            if technique['technique'] == "Account Manipulation":
                techniques.append(ot.AccountManipulation("account-manipulation"))
            if technique['technique'] == "Local Job Scheduling":
                techniques.append(ot.LocalJobScheduling("local-job-scheduling"))
            if technique['technique'] == "AppInit DLLs":
                techniques.append(ot.AppInitDLLs("appinit-dlls"))
            if technique['technique'] == "Transport Agent":
                techniques.append(ot.TransportAgent("transport-agent"))
            if technique['technique'] == "Socket Filters":
                techniques.append(ot.SocketFilters("socket-filters"))
            if technique['technique'] == "Office Application Startup":
                techniques.append(ot.OfficeApplicationStartup("office-application-startup"))
            if technique['technique'] == "Bootkit":
                techniques.append(ot.Bootkit("bootkit"))
            if technique['technique'] == "New Service":
                techniques.append(ot.NewService("new-service"))
            if technique['technique'] == "DLL":
                techniques.append(ot.DLL("dll"))
            if technique['technique'] == "Print Processors":
                techniques.append(ot.PrintProcessors("print-processors"))
            if technique['technique'] == "Device Registration":
                techniques.append(ot.DeviceRegistration("device-registration"))
            if technique['technique'] == "Path Interception by PATH Environment Variable":
                techniques.append(ot.PathInterceptionByPATHEnvironmentVariable("path-interception-by-path-environment-variable"))
            if technique['technique'] == "Scheduled Task":
                techniques.append(ot.ScheduledTask("scheduled-task"))
            if technique['technique'] == "Installer Packages":
                techniques.append(ot.InstallerPackages("installer-packages"))
            if technique['technique'] == "Hijack Execution Flow":
                techniques.append(ot.HijackExecutionFlow("hijack-execution-flow"))
            if technique['technique'] == "Local Account":
                techniques.append(ot.LocalAccount("local-account"))
            if technique['technique'] == "Port Monitors":
                techniques.append(ot.PortMonitors("port-monitors"))
            if technique['technique'] == "Winlogon Helper DLL":
                techniques.append(ot.WinlogonHelperDLL("winlogon-helper-dll"))
            if technique['technique'] == "BITS Jobs":
                techniques.append(ot.BITSJobs("bits-jobs"))
            if technique['technique'] == "Windows Management Instrumentation Event Subscription":
                techniques.append(ot.WindowsManagementInstrumentationEventSubscription("windows-management-instrumentation-event-subscription"))
            if technique['technique'] == "Services File Permissions Weakness":
                techniques.append(ot.ServicesFilePermissionsWeakness("services-file-permissions-weakness"))
            if technique['technique'] == "PowerShell Profile":
                techniques.append(ot.PowerShellProfile("powershell-profile"))
            if technique['technique'] == "Event Triggered Execution":
                techniques.append(ot.EventTriggeredExecution("event-triggered-execution"))
            if technique['technique'] == "Change Default File Association":
                techniques.append(ot.ChangeDefaultFileAssociation("change-default-file-association"))
            if technique['technique'] == "Web Shell":
                techniques.append(ot.WebShell("web-shell"))
            if technique['technique'] == 'Boot or Logon Initialization Scripts':
                techniques.append(ot.BootOrLogonInitializationScripts("boot-or-logon-initialization-scripts"))
            if technique['technique'] == 'Logon Script (Windows)':
                techniques.append(ot.LogonScriptWindows("logon-script-windows"))
            if technique['technique'] == 'Login Hook':
                techniques.append(ot.LoginHook("login-hook"))
            if technique['technique'] == 'Network Logon Script':
                techniques.append(ot.NetworkLogonScript("network-logon-script"))
            if technique['technique'] == 'RC Scripts':
                techniques.append(ot.RCScripts("rc-scripts"))
            if technique['technique'] == 'Startup Items':
                techniques.append(ot.StartupItems("startup-items"))
            if technique['technique'] == 'Additional Cloud Credentials':
                techniques.append(ot.AdditionalCloudCredentials("additional-cloud-credentials"))
            if technique['technique'] == 'Additional Email Delegate Permissions':
                techniques.append(ot.AdditionalEmailDelegatePermissions("additional-email-delegate-permissions"))
            if technique['technique'] == 'Additional Cloud Roles':
                techniques.append(ot.AdditionalCloudRoles("additional-cloud-roles"))
            if technique['technique'] == 'SSH Authorized Keys':
                techniques.append(ot.SSHAuthorizedKeys("ssh-authorized-keys"))
            if technique['technique'] == 'Additional Container Cluster Roles':
                techniques.append(ot.AdditionalContainerClusterRoles("additional-container-cluster-roles"))
            if technique['technique'] == 'Additional Local or Domain Groups':
                techniques.append(ot.AdditionalLocalOrDomainGroups("additional-local-or-domain-groups"))
            if technique['technique'] == 'Create Account':
                techniques.append(ot.CreateAccount("create-account"))
            if technique['technique'] == 'Office Template Macros':
                techniques.append(ot.OfficeTemplateMacros("office-template-macros"))
            if technique['technique'] == 'Office Test':
                techniques.append(ot.OfficeTest("office-test"))
            if technique['technique'] == 'Outlook Forms':
                techniques.append(ot.OutlookForms("outlook-forms"))
            if technique['technique'] == 'Outlook Home Page':
                techniques.append(ot.OutlookHomePage("outlook-home-page"))
            if technique['technique'] == 'Outlook Rules':
                techniques.append(ot.OutlookRules("outlook-rules"))
            if technique['technique'] == 'Add-ins':
                techniques.append(ot.AddIns("add-ins"))
            if technique['technique'] == 'Software Extensions':
                techniques.append(ot.SoftwareExtensions("software-extensions"))
            if technique['technique'] == 'Browser Extensions':
                techniques.append(ot.BrowserExtensions("browser-extensions"))
            if technique['technique'] == 'IDE Extensions':
                techniques.append(ot.IDEExtensions("ide-extensions"))
            if technique['technique'] == 'Port Knocking':
                techniques.append(ot.PortKnocking("port-knocking"))
            if technique['technique'] == 'Server Software Component':
                techniques.append(ot.ServerSoftwareComponent("server-software-component"))
            if technique['technique'] == 'SQL Stored Procedures':
                techniques.append(ot.SQLStoredProcedures("sql-stored-procedures"))
            if technique['technique'] == 'IIS Components':
                techniques.append(ot.IISComponents("iis-components"))
            if technique['technique'] == 'Terminal Services DLL':
                techniques.append(ot.TerminalServicesDLL("terminal-services-dll"))
            if technique['technique'] == 'Implant Internal Image':
                techniques.append(ot.ImplantInternalImage("implant-internal-image"))
            if technique['technique'] == 'Pre-OS Boot':
                techniques.append(ot.PreOSBoot("pre-os-boot"))
            if technique['technique'] == 'System Firmware':
                techniques.append(ot.SystemFirmware("system-firmware"))
            if technique['technique'] == 'Component Firmware':
                techniques.append(ot.ComponentFirmware("component-firmware"))
            if technique['technique'] == 'ROMMONkit':
                techniques.append(ot.ROMMONkit("rommonkit"))
            if technique['technique'] == 'TFTP Boot':
                techniques.append(ot.TFTPBoot("tftp-boot"))
            if technique['technique'] == 'Launch Agent':
                techniques.append(ot.LaunchAgent("launch-agent"))
            if technique['technique'] == 'Systemd Service':
                techniques.append(ot.SystemdService("systemd-service"))
            if technique['technique'] == 'Launch Daemon':
                techniques.append(ot.LaunchDaemon("launch-daemon"))
            if technique['technique'] == 'Container Service':
                techniques.append(ot.ContainerService("container-service"))
            if technique['technique'] == 'Screensaver':
                techniques.append(ot.Screensaver("screensaver"))
            if technique['technique'] == 'Unix Shell Configuration Modification':
                techniques.append(ot.UnixShellConfigurationModification("unix-shell-configuration-modification"))
            if technique['technique'] == 'Trap':
                techniques.append(ot.Trap("trap"))
            if technique['technique'] == 'LC_LOAD_DYLIB Addition':
                techniques.append(ot.LCLoadDylibAddition("lc-load-dylib-addition"))
            if technique['technique'] == 'Netsh Helper DLL':
                techniques.append(ot.NetshHelperDLL("netsh-helper-dll"))
            if technique['technique'] == 'Accessibility Features':
                techniques.append(ot.AccessibilityFeatures("accessibility-features"))
            if technique['technique'] == 'AppCert DLLs':
                techniques.append(ot.AppCertDLLs("appcert-dlls"))
            if technique['technique'] == 'Application Shimming':
                techniques.append(ot.ApplicationShimming("application-shimming"))
            if technique['technique'] == 'Image File Execution Options Injection':
                techniques.append(ot.ImageFileExecutionOptionsInjection("image-file-execution-options-injection"))
            if technique['technique'] == 'Emond':
                techniques.append(ot.Emond("emond"))
            if technique['technique'] == 'Udev Rules':
                techniques.append(ot.UdevRules("udev-rules"))
            if technique['technique'] == 'Python Startup Hooks':
                techniques.append(ot.PythonStartupHooks("python-startup-hooks"))
            if technique['technique'] == 'Authentication Package':
                techniques.append(ot.AuthenticationPackage("authentication-package"))
            if technique['technique'] == 'Time Providers':
                techniques.append(ot.TimeProviders("time-providers"))
            if technique['technique'] == 'Security Support Provider':
                techniques.append(ot.SecuritySupportProvider("security-support-provider"))
            if technique['technique'] == 'Re-opened Applications':
                techniques.append(ot.ReopenedApplications("reopened-applications"))
            if technique['technique'] == 'LSASS Driver':
                techniques.append(ot.LSASSDriver("lsass-driver"))
            if technique['technique'] == 'XDG Autostart Entries':
                techniques.append(ot.XDGAutostartEntries("xdg-autostart-entries"))
            if technique['technique'] == 'Active Setup':
                techniques.append(ot.ActiveSetup("active-setup"))
            if technique['technique'] == 'Login Items':
                techniques.append(ot.LoginItems("login-items"))
            if technique['technique'] == 'Compromise Host Software Binary':
                techniques.append(ot.CompromiseHostSoftwareBinary("compromise-host-software-binary"))
            if technique['technique'] == 'Modify Authentication Process':
                techniques.append(ot.ModifyAuthenticationProcess("modify-authentication-process"))
            if technique['technique'] == 'Domain Controller Authentication':
                techniques.append(ot.DomainControllerAuthentication("domain-controller-authentication"))
            if technique['technique'] == 'Password Filter DLL':
                techniques.append(ot.PasswordFilterDLL("password-filter-dll"))
            if technique['technique'] == 'Pluggable Authentication Modules':
                techniques.append(ot.PluggableAuthenticationModules("pluggable-authentication-modules"))
            if technique['technique'] == 'Network Device Authentication':
                techniques.append(ot.NetworkDeviceAuthentication("network-device-authentication"))
            if technique['technique'] == 'Reversible Encryption':
                techniques.append(ot.ReversibleEncryption("reversible-encryption"))
            if technique['technique'] == 'Multi-Factor Authentication':
                techniques.append(ot.MultiFactorAuthentication("multi-factor-authentication"))
            if technique['technique'] == 'Hybrid Identity':
                techniques.append(ot.HybridIdentity("hybrid-identity"))
            if technique['technique'] == 'Network Provider DLL':
                techniques.append(ot.NetworkProviderDLL("network-provider-dll"))
            if technique['technique'] == 'Conditional Access Policies':
                techniques.append(ot.ConditionalAccessPolicies("conditional-access-policies"))
            if technique['technique'] == 'Dylib Hijacking':
                techniques.append(ot.DylibHijacking("dylib-hijacking"))
            if technique['technique'] == 'Executable Installer File Permissions Weakness':
                techniques.append(ot.ExecutableInstallerFilePermissionsWeakness("executable-installer-file-permissions-weakness"))
            if technique['technique'] == 'Dynamic Linker Hijacking':
                techniques.append(ot.DynamicLinkerHijacking("dynamic-linker-hijacking"))
            if technique['technique'] == 'Path Interception by Search Order Hijacking':
                techniques.append(ot.PathInterceptionBySearchOrderHijacking("path-interception-by-search-order-hijacking"))
            if technique['technique'] == 'Path Interception by Unquoted Path':
                techniques.append(ot.PathInterceptionByUnquotedPath("path-interception-by-unquoted-path"))
            if technique['technique'] == 'Services Registry Permissions Weakness':
                techniques.append(ot.ServicesRegistryPermissionsWeakness("services-registry-permissions-weakness"))
            if technique['technique'] == 'COR_PROFILER':
                techniques.append(ot.CORProfiler("cor-profiler"))
            if technique['technique'] == 'KernelCallbackTable':
                techniques.append(ot.KernelCallbackTable("kernel-callback-table"))
            if technique['technique'] == 'AppDomainManager':
                techniques.append(ot.AppDomainManager("app-domain-manager"))
            if technique['technique'] == 'Exclusive Control':
                techniques.append(ot.ExclusiveControl("exclusive-control"))
            if technique['technique'] == 'Cloud Application Integration':
                techniques.append(ot.CloudApplicationIntegration("cloud-application-integration"))

        # PRIVILEGE ESCALATION
        if technique['tactic'] == 'Privilege Escalation':
            if technique['technique'] == 'Process Injection':
                techniques.append(ot.ProcessInjection("process-injection"))
            if technique['technique'] == 'Hooking':
                techniques.append(ot.Hooking("hooking"))
            if technique['technique'] == 'Dynamic-link Library Injection':
                techniques.append(ot.DLLInjection("dll-injection"))
            if technique['technique'] == 'Create or Modify System Process':
                techniques.append(ot.CreateOrModifySystemProcess("create-or-modify-system-process"))
            if technique['technique'] == 'Access Token Manipulation':
                techniques.append(ot.AccessTokenManipulation("access-token-manipulation"))
            if technique['technique'] == 'Windows Service':
                techniques.append(ot.WindowsService("windows-service"))
            if technique['technique'] == 'Token Impersonation/Theft':
                techniques.append(ot.TokenImpersonationTheft("token-impersonation-theft"))
            if technique['technique'] == 'Extra Window Memory Injection':
                techniques.append(ot.ExtraWindowMemoryInjection("extra-window-memory-injection"))
            if technique['technique'] == 'Thread Execution Hijacking':
                techniques.append(ot.ThreadExecutionHijacking("thread-execution-hijacking"))
            if technique['technique'] == 'Component Object Model Hijacking':
                techniques.append(ot.ComponentObjectModelHijacking("component-object-model-hijacking"))
            if technique['technique'] == 'Boot or Logon Autostart Execution':
                techniques.append(ot.BootOrLogonAutostartExecution("boot-or-logon-autostart-execution"))
            if technique['technique'] == 'Registry Run Keys / Startup Folder':
                techniques.append(ot.RegistryRunKeysStartupFolder("registry-run-keys-startup-folder"))
            if technique['technique'] == 'Process Hollowing':
                techniques.append(ot.ProcessHollowing("process-hollowing"))
            if technique['technique'] == 'Abuse Elevation Control Mechanism':
                techniques.append(ot.AbuseElevationControlMechanism("abuse-elevation-control-mechanism"))
            if technique['technique'] == 'Account Manipulation':
                techniques.append(ot.AccountManipulation("account-manipulation"))
            if technique['technique'] == 'ListPlanting':
                techniques.append(ot.ListPlanting("list-planting"))
            if technique['technique'] == 'Make and Impersonate Token':
                techniques.append(ot.MakeAndImpersonateToken("make-and-impersonate-token"))
            if technique['technique'] == 'DLL Side-Loading':
                techniques.append(ot.DLLSideLoading("dll-side-loading"))
            if technique['technique'] == 'Kernel Modules and Extensions':
                techniques.append(ot.KernelModulesAndExtensions("kernel-modules-and-extensions"))
            if technique['technique'] == 'Shortcut Modification':
                techniques.append(ot.ShortcutModification("shortcut-modification"))
            if technique['technique'] == 'DLL Search Order Hijacking':
                techniques.append(ot.DLLSearchOrderHijacking("dll-search-order-hijacking"))
            if technique['technique'] == 'Create Process with Token':
                techniques.append(ot.CreateProcessWithToken("create-process-with-token"))
            if technique['technique'] == 'Asynchronous Procedure Calls':
                techniques.append(ot.AsynchronousProcedureCalls("asynchronous-procedure-calls"))
            if technique['technique'] == 'Exploitation for Privilege Escalation':
                techniques.append(ot.ExploitationForPrivilegeEscalation("exploitation-for-escalation"))
            if technique['technique'] == 'Portable Executable Injection':
                techniques.append(ot.PortableExecutableInjection("portable-executable-injection"))
            if technique['technique'] == 'New Service':
                techniques.append(ot.NewService("new-service"))
            if technique['technique'] == 'DLL':
                techniques.append(ot.DLL("dll"))
            if technique['technique'] == 'Print Processors':
                techniques.append(ot.PrintProcessors("print-processors"))
            if technique['technique'] == 'Device Registration':
                techniques.append(ot.DeviceRegistration("device-registration"))
            if technique['technique'] == 'Path Interception by PATH Environment Variable':
                techniques.append(ot.PathInterceptionByPATHEnvironmentVariable("path-interception-by-path-environment-variable"))
            if technique['technique'] == 'Thread Local Storage':
                techniques.append(ot.ThreadLocalStorage("thread-local-storage"))
            if technique['technique'] == 'Bypass User Account Control':
                techniques.append(ot.BypassUserAccountControl("bypass-user-account-control"))
            if technique['technique'] == 'Service File Permissions Weakness':
                techniques.append(ot.ServiceFilePermissionsWeakness("service-file-permissions-weakness"))
            if technique['technique'] == 'Scheduled Task':
                techniques.append(ot.ScheduledTask("scheduled-task"))
            if technique['technique'] == 'Installer Packages':
                techniques.append(ot.InstallerPackages("installer-packages"))
            if technique['technique'] == 'File System Permissions Weakness':
                techniques.append(ot.FileSystemPermissionsWeakness("file-system-permissions-weakness"))
            if technique['technique'] == 'Hijack Execution Flow':
                techniques.append(ot.HijackExecutionFlow("hijack-execution-flow"))
            if technique['technique'] == 'Process Doppelgänging':
                techniques.append(ot.ProcessDoppelganging("process-doppelganging"))
            if technique['technique'] == 'Port Monitors':
                techniques.append(ot.PortMonitors("port-monitors"))
            if technique['technique'] == 'Winlogon Helper DLL':
                techniques.append(ot.WinlogonHelperDLL("winlogon-helper-dll"))
            if technique['technique'] == 'AppInit DLLs':
                techniques.append(ot.AppInitDLLs("appinit-dlls"))
            if technique['technique'] == 'Windows Management Instrumentation Event Subscription':
                techniques.append(ot.WindowsManagementInstrumentationEventSubscription("windows-management-instrumentation-event-subscription"))
            if technique['technique'] == 'PowerShell Profile':
                techniques.append(ot.PowerShellProfile("powershell-profile"))
            if technique['technique'] == 'Change Default File Association':
                techniques.append(ot.ChangeDefaultFileAssociation("change-default-file-association"))
            if technique['technique'] == 'Group Policy Modification':
                techniques.append(ot.GroupPolicyModification("group-policy-modification"))
            if technique['technique'] == 'Event Triggered Execution':
                techniques.append(ot.EventTriggeredExecution("event-triggered-execution"))
            if technique['technique'] == 'Valid Accounts':
                techniques.append(ot.ValidAccounts("valid-accounts"))
            if technique['technique'] == 'Domain or Tenant Policy Modification':
                techniques.append(ot.DomainOrTenantPolicyModification("domain-or-tenant-policy-modification"))
            if technique['technique'] == 'Escape to Host':
                techniques.append(ot.EscapeToHost("escape-to-host"))
            if technique['technique'] == 'Ptrace System Calls':
                techniques.append(ot.PtraceSystemCalls("ptrace-system-calls"))
            if technique['technique'] == 'Proc Memory':
                techniques.append(ot.ProcMemory("proc-memory"))
            if technique['technique'] == 'VDSO Hijacking':
                techniques.append(ot.VDSOHijacking("vdso-hijacking"))
            if technique['technique'] == 'Parent PID Spoofing':
                techniques.append(ot.ParentPIDSpoofing("parent-pid-spoofing"))
            if technique['technique'] == 'SID-History Injection':
                techniques.append(ot.SIDHistoryInjection("sid-history-injection"))
            if technique['technique'] == 'Trust Modification':
                techniques.append(ot.TrustModification("trust-modification"))
            if technique['technique'] == 'Setuid and Setgid':
                techniques.append(ot.SetuidAndSetgid("setuid-and-setgid"))
            if technique['technique'] == 'Sudo and Sudo Caching':
                techniques.append(ot.SudoAndSudoCaching("sudo-and-sudo-caching"))
            if technique['technique'] == 'Elevated Execution with Prompt':
                techniques.append(ot.ElevatedExecutionWithPrompt("elevated-execution-with-prompt"))
            if technique['technique'] == 'Temporary Elevated Cloud Access':
                techniques.append(ot.TemporaryElevatedCloudAccess("temporary-elevated-cloud-access"))
            if technique['technique'] == 'TCC Manipulation':
                techniques.append(ot.TCCManipulation("tcc-manipulation"))
            
        # DEFENSE EVASION
        if technique['tactic'] == 'Defense Evasion':
            if technique['technique'] == 'Code Signing':
                techniques.append(ot.CodeSigning("code-signing"))
            if technique['technique'] == 'Software Packing':
                techniques.append(ot.SoftwarePacking("software-packing"))
            if technique['technique'] == 'Process Injection':
                techniques.append(ot.ProcessInjection("process-injection"))
            if technique['technique'] == 'Modify Registry':
                techniques.append(ot.ModifyRegistry("modify-registry"))
            if technique['technique'] == 'File Deletion':
                techniques.append(ot.FileDeletion("file-deletion"))
            if technique['technique'] == 'Virtualization/Sandbox Evasion':
                techniques.append(ot.VirtualizationSandboxEvasion("virtualization-sandbox-evasion"))
            if technique['technique'] == 'Obfuscated Files or Information':
                techniques.append(ot.ObfuscatedFilesOrInformation("obfuscated-files-or-information"))
            if technique['technique'] == 'Debugger Evasion':
                techniques.append(ot.DebuggerEvasion("debugger-evasion"))
            if technique['technique'] == 'Dynamic-link Library Injection':
                techniques.append(ot.DLLInjection("dll-injection"))
            if technique['technique'] == 'Time Based Evasion':
                techniques.append(ot.TimeBasedEvasion("time-based-evasion"))
            if technique['technique'] == 'Execution Guardrails':
                techniques.append(ot.ExecutionGuardrails("execution-guardrails"))
            if technique['technique'] == 'Token Impersonation/Theft':
                techniques.append(ot.TokenImpersonationTheft("token-impersonation-theft"))
            if technique['technique'] == 'Timestomp':
                techniques.append(ot.Timestomp("timestomp"))
            if technique['technique'] == 'Extra Window Memory Injection':
                techniques.append(ot.ExtraWindowMemoryInjection("extra-window-memory-injection"))
            if technique['technique'] == 'Access Token Manipulation':
                techniques.append(ot.AccessTokenManipulation("access-token-manipulation"))
            if technique['technique'] == 'Hidden Window':
                techniques.append(ot.HiddenWindow("hidden-window"))
            if technique['technique'] == 'Dynamic API Resolution':
                techniques.append(ot.DynamicAPIResolution("dynamic-api-resolution"))
            if technique['technique'] == 'Deobfuscate/Decode Files or Information':
                techniques.append(ot.DeobfuscateDecodeFilesOrInformation("deobfuscate-decode-files-or-information"))
            if technique['technique'] == 'Thread Execution Hijacking':
                techniques.append(ot.ThreadExecutionHijacking("thread-execution-hijacking"))
            if technique['technique'] == 'Masquerading':
                techniques.append(ot.Masquerading("masquerading"))
            if technique['technique'] == 'Embedded Payloads':
                techniques.append(ot.EmbeddedPayloads("embedded-payloads"))
            if technique['technique'] == 'Indicator Removal from Tools':
                techniques.append(ot.IndicatorRemovalFromTools("indicator-removal-from-tools"))
            if technique['technique'] == 'Hide Artifacts':
                techniques.append(ot.HideArtifacts("hide-artifacts"))
            if technique['technique'] == 'User Activity Based Checks':
                techniques.append(ot.UserActivityBasedChecks("user-activity-based-checks"))
            if technique['technique'] == 'File and Directory Permissions Modification':
                techniques.append(ot.FileAndDirectoryPermissionsModification("file-and-directory-permissions-modification"))
            if technique['technique'] == 'Process Hollowing':
                techniques.append(ot.ProcessHollowing("process-hollowing"))
            if technique['technique'] == 'Abuse Elevation Control Mechanism':
                techniques.append(ot.AbuseElevationControlMechanism("abuse-elevation-control-mechanism"))
            if technique['technique'] == 'System Checks':
                techniques.append(ot.SystemChecks("system-checks"))
            if technique['technique'] == 'ListPlanting':
                techniques.append(ot.ListPlanting("list-planting"))
            if technique['technique'] == 'Indicator Removal':
                techniques.append(ot.IndicatorRemoval("indicator-removal"))
            if technique['technique'] == 'Make and Impersonate Token':
                techniques.append(ot.MakeAndImpersonateToken("make-and-impersonate-token"))
            if technique['technique'] == 'DLL Side-Loading':
                techniques.append(ot.DLLSideLoading("dll-side-loading"))
            if technique['technique'] == 'DLL Search Order Hijacking':
                techniques.append(ot.DLLSearchOrderHijacking("dll-search-order-hijacking"))
            if technique['technique'] == 'Reflective Code Loading':
                techniques.append(ot.ReflectiveCodeLoading("reflective-code-loading"))
            if technique['technique'] == 'Encrypted/Encoded File':
                techniques.append(ot.EncryptedEncodedFile("encrypted-encoded-file"))
            if technique['technique'] == 'Create Process with Token':
                techniques.append(ot.CreateProcessWithToken("create-process-with-token"))
            if technique['technique'] == 'Disable or Modify Tools':
                techniques.append(ot.DisableOrModifyTools("disable-or-modify-tools"))
            if technique['technique'] == 'Msiexec':
                techniques.append(ot.Msiexec("msiexec"))
            if technique['technique'] == 'Asynchronous Procedure Call':
                techniques.append(ot.AsynchronousProcedureCall("asynchronous-procedure-call"))
            if technique['technique'] == 'Regsvr32':
                techniques.append(ot.Regsvr32("regsvr32"))
            if technique['technique'] == 'Portable Executable Injection':
                techniques.append(ot.PortableExecutableInjection("portable-executable-injection"))
            if technique['technique'] == 'DLL':
                techniques.append(ot.DLL("dll"))
            if technique['technique'] == 'Direct Volume Access':
                techniques.append(ot.DirectVolumeAccess("direct-volume-access"))
            if technique['technique'] == 'NTFS File Attributes':
                techniques.append(ot.NTFSFileAttributes("ntfs-file-attributes"))
            if technique['technique'] == 'Path Interception by PATH Environment Variable':
                techniques.append(ot.PathInterceptionByPATHEnvironmentVariable("path-interception-by-path-environment-variable"))
            if technique['technique'] == 'Thread Local Storage':
                techniques.append(ot.ThreadLocalStorage("thread-local-storage"))
            if technique['technique'] == 'Bypass User Account Control':
                techniques.append(ot.BypassUserAccountControl("bypass-user-account-control"))
            if technique['technique'] == 'Socket Filters':
                techniques.append(ot.SocketFilters("socket-filters"))
            if technique['technique'] == 'Rootkit':
                techniques.append(ot.Rootkit("rootkit"))
            if technique['technique'] == 'Clear Windows Event Logs':
                techniques.append(ot.ClearWindowsEventLogs("clear-windows-event-logs"))
            if technique['technique'] == 'Rundll32':
                techniques.append(ot.Rundll32("rundll32"))
            if technique['technique'] == 'Masquerade File Type':
                techniques.append(ot.MasqueradeFileType("masquerade-file-type"))
            if technique['technique'] == 'Services File Permissions Weakness':
                techniques.append(ot.ServicesFilePermissionsWeakness("services-file-permissions-weakness"))
            if technique['technique'] == 'Code Signing Policy Modification':
                techniques.append(ot.CodeSigningPolicyModification("code-signing-policy-modification"))
            if technique['technique'] == 'Install Root Certificate':
                techniques.append(ot.InstallRootCertificate("install-root-certificate"))
            if technique['technique'] == 'Indicator Removal on Host':
                techniques.append(ot.IndicatorRemovalOnHost("indicator-removal-on-host"))
            if technique['technique'] == 'Hijack Execution Flow':
                techniques.append(ot.HijackExecutionFlow("hijack-execution-flow"))
            if technique['technique'] == 'Bootkit':
                techniques.append(ot.Bootkit("bootkit"))
            if technique['technique'] == 'Clear Persistence':
                techniques.append(ot.ClearPersistence("clear-persistence"))
            if technique['technique'] == 'Process Doppelgänging':
                techniques.append(ot.ProcessDoppelganging("process-doppelganging"))
            if technique['technique'] == 'Scripting':
                techniques.append(ot.Scripting("scripting"))
            if technique['technique'] == 'Binary Padding':
                techniques.append(ot.BinaryPadding("binary-padding"))
            if technique['technique'] == 'System Binary Proxy Execution':
                techniques.append(ot.SystemBinaryProxyExecution("system-binary-proxy-execution"))
            if technique['technique'] == 'Impair Defenses':
                techniques.append(ot.ImpairDefenses("impair-defenses"))
            if technique['technique'] == 'Masquerade Task or Service':
                techniques.append(ot.MasqueradeTaskOrService("masquerade-task-or-service"))
            if technique['technique'] == 'Regsvcs/Regasm':
                techniques.append(ot.RegsvcsRegasm("regsvcs-regasm"))
            if technique['technique'] == 'Compile After Delivery':
                techniques.append(ot.CompileAfterDelivery("compile-after-delivery"))
            if technique['technique'] == 'Match Legitimate Name or Location':
                techniques.append(ot.MatchLegitimateNameOrLocation("match-legitimate-name-or-location"))
            if technique['technique'] == 'Clear Command History':
                techniques.append(ot.ClearCommandHistory("clear-command-history"))
            if technique['technique'] == 'MSBuild':
                techniques.append(ot.MSBuild("msbuild"))
            if technique['technique'] == 'Rename System Utilities':
                techniques.append(ot.RenameSystemUtilities("rename-system-utilities"))
            if technique['technique'] == 'Double File Extension':
                techniques.append(ot.DoubleFileExtension("double-file-extension"))
            if technique['technique'] == 'Disable or Modify System Firewall':
                techniques.append(ot.DisableOrModifySystemFirewall("disable-or-modify-system-firewall"))
            if technique['technique'] == 'Match Legitimate Name or Location':
                techniques.append(ot.MatchLegitimateNameOrLocation("match-legitimate-name-or-location"))
            if technique['technique'] == 'Compression':
                techniques.append(ot.Compression("compression"))
            if technique['technique'] == 'Hidden File System':
                techniques.append(ot.HiddenFileSystem("hidden-file-system"))
            if technique['technique'] == 'Windows File and Directory Permissions Modification':
                techniques.append(ot.WindowsFileAndDirectoryPermissionsModification("windows-file-and-directory-permissions-modification"))
            if technique['technique'] == 'Rename Legitimate Utilities':
                techniques.append(ot.RenameLegitimateUtilities("rename-legitimate-utilities"))
            if technique['technique'] == 'Mshta':
                techniques.append(ot.Mshta("mshta"))
            if technique['technique'] == 'Odbcconf':
                techniques.append(ot.Odbcconf("odbcconf"))
            if technique['technique'] == 'Command Obfuscation':
                techniques.append(ot.CommandObfuscation("command-obfuscation"))
            if technique['technique'] == 'HTML Smuggling':
                techniques.append(ot.HTMLSmuggling("html-smuggling"))
            if technique['technique'] == 'Trusted Developer Utilities Proxy Execution':
                techniques.append(ot.TrustedDeveloperUtilitiesProxyExecution("trusted-developer-utilities-proxy-execution"))
            if technique['technique'] == 'Indirect Command Execution':
                techniques.append(ot.IndirectCommandExecution("indirect-command-execution"))
            if technique['technique'] == 'Group Policy Modification':
                techniques.append(ot.GroupPolicyModification("group-policy-modification"))
            if technique['technique'] == 'Stripped Payloads':
                techniques.append(ot.StrippedPayloads("stripped-payloads"))
            if technique['technique'] == 'Fileless Storage':
                techniques.append(ot.FilelessStorage("fileless-storage"))
            if technique['technique'] == 'LNK Icon Smuggling':
                techniques.append(ot.LNKIconSmuggling("lnk-icon-smuggling"))
            if technique['technique'] == 'Polymorphic Code':
                techniques.append(ot.PolymorphicCode("polymorphic-code"))
            if technique['technique'] == 'Junk Code Insertion':
                techniques.append(ot.JunkCodeInsertion("junk-code-insertion"))
            if technique['technique'] == 'Invalid Code Signature':
                techniques.append(ot.InvalidCodeSignature("invalid-code-signature"))
            if technique['technique'] == 'Right-to-Left Override':
                techniques.append(ot.RightToLeftOverride("right-to-left-override"))
            if technique['technique'] == 'Match Legitimate Resource Name or Location':
                techniques.append(ot.MatchLegitimateResourceNameOrLocation("match-legitimate-resource-name-or-location"))
            if technique['technique'] == 'Space after Filename':
                techniques.append(ot.SpaceAfterFilename("space-after-filename"))
            if technique['technique'] == 'Break Process Trees':
                techniques.append(ot.BreakProcessTrees("break-process-trees"))
            if technique['technique'] == 'Masquerade Account Name':
                techniques.append(ot.MasqueradeAccountName("masquerade-account-name"))
            if technique['technique'] == 'Rename Legitimate Files':
                techniques.append(ot.RenameLegitimateFiles("rename-legitimate-files"))
            if technique['technique'] == 'Browser Fingerprint':
                techniques.append(ot.BrowserFingerprint("browser-fingerprint"))
            if technique['technique'] == 'Clear Linux or Mac System Logs':
                techniques.append(ot.ClearLinuxOrMacSystemLogs("clear-linux-or-mac-system-logs"))
            if technique['technique'] == 'Network Share Connection Removal':
                techniques.append(ot.NetworkShareConnectionRemoval("network-share-connection-removal"))
            if technique['technique'] == 'Clear Network Connection History and Configurations':
                techniques.append(ot.ClearNetworkConnectionHistoryAndConfigurations("clear-network-connection-history-and-configurations"))
            if technique['technique'] == 'Clear Mailbox Data':
                techniques.append(ot.ClearMailboxData("clear-mailbox-data"))
            if technique['technique'] == 'Relocate Malware':
                techniques.append(ot.RelocateMalware("relocate-malware"))
            if technique['technique'] == 'External Proxy':
                techniques.append(ot.ExternalProxy("external-proxy"))
            if technique['technique'] == 'Domain Fronting':
                techniques.append(ot.DomainFronting("domain-fronting"))
            if technique['technique'] == 'ClickOnce':
                techniques.append(ot.ClickOnce("clickonce"))
            if technique['technique'] == 'JamPlus':
                techniques.append(ot.JamPlus("jamplus"))
            if technique['technique'] == 'Rogue Domain Controller':
                techniques.append(ot.RogueDomainController("rogue-domain-controller"))
            if technique['technique'] == 'Exploitation for Defense Evasion':
                techniques.append(ot.ExploitationForDefenseEvasion("exploitation-for-defense-evasion"))
            if technique['technique'] == 'System Script Proxy Execution':
                techniques.append(ot.SystemScriptProxyExecution("system-script-proxy-execution"))
            if technique['technique'] == 'PubPrn':
                techniques.append(ot.PubPrn("pubprn"))
            if technique['technique'] == 'SyncAppvPublishingServer':
                techniques.append(ot.SyncAppvPublishingServer("syncappvpublishingserver"))
            if technique['technique'] == 'Compiled HTML File':
                techniques.append(ot.CompiledHTMLFile("compiled-html-file"))
            if technique['technique'] == 'Control Panel':
                techniques.append(ot.ControlPanel("control-panel"))
            if technique['technique'] == 'CMSTP':
                techniques.append(ot.CMSTP("cmstp"))
            if technique['technique'] == 'InstallUtil':
                techniques.append(ot.InstallUtil("installutil"))
            if technique['technique'] == 'Verclsid':
                techniques.append(ot.Verclsid("verclsid"))
            if technique['technique'] == 'Mavinject':
                techniques.append(ot.Mavinject("mavinject"))
            if technique['technique'] == 'MMC':
                techniques.append(ot.MMC("mmc"))
            if technique['technique'] == 'Electron Applications':
                techniques.append(ot.ElectronApplications("electron-applications"))
            if technique['technique'] == 'XSL Script Processing':
                techniques.append(ot.XSLScriptProcessing("xsl-script-processing"))
            if technique['technique'] == 'Template Injection':
                techniques.append(ot.TemplateInjection("template-injection"))
            if technique['technique'] == 'Linux and Mac File and Directory Permissions Modification':
                techniques.append(ot.LinuxAndMacFileAndDirectoryPermissionsModification("linux-and-mac-file-and-directory-permissions-modification"))
            if technique['technique'] == 'Environmental Keying':
                techniques.append(ot.EnvironmentalKeying("environmental-keying"))
            if technique['technique'] == 'Mutual Exclusion':
                techniques.append(ot.MutualExclusion("mutual-exclusion"))
            if technique['technique'] == 'Unused/Unsupported Cloud Regions':
                techniques.append(ot.UnusedUnsupportedCloudRegions("unused-unsupported-cloud-regions"))
            if technique['technique'] == 'Use Alternate Authentication Material':
                techniques.append(ot.UseAlternateAuthenticationMaterial("use-alternate-authentication-material"))
            if technique['technique'] == 'Application Access Token':
                techniques.append(ot.ApplicationAccessToken("application-access-token"))
            if technique['technique'] == 'Pass the Ticket':
                techniques.append(ot.PassTheTicket("pass-the-ticket"))
            if technique['technique'] == 'Web Session Cookie':
                techniques.append(ot.WebSessionCookie("web-session-cookie"))
            if technique['technique'] == 'Subvert Trust Controls':
                techniques.append(ot.SubvertTrustControls("subvert-trust-controls"))
            if technique['technique'] == 'Gatekeeper Bypass':
                techniques.append(ot.GatekeeperBypass("gatekeeper-bypass"))
            if technique['technique'] == 'SIP and Trust Provider Hijacking':
                techniques.append(ot.SIPAndTrustProviderHijacking("sip-and-trust-provider-hijacking"))
            if technique['technique'] == 'Mark-of-the-Web Bypass':
                techniques.append(ot.MarkOfTheWebBypass("mark-of-the-web-bypass"))
            if technique['technique'] == 'Disable Windows Event Logging':
                techniques.append(ot.DisableWindowsEventLogging("disable-windows-event-logging"))
            if technique['technique'] == 'Impair Command History Logging':
                techniques.append(ot.ImpairCommandHistoryLogging("impair-command-history-logging"))
            if technique['technique'] == 'Indicator Blocking':
                techniques.append(ot.IndicatorBlocking("indicator-blocking"))
            if technique['technique'] == 'Disable or Modify Cloud Firewall':
                techniques.append(ot.DisableOrModifyCloudFirewall("disable-or-modify-cloud-firewall"))
            if technique['technique'] == 'Disable or Modify Cloud Logs':
                techniques.append(ot.DisableOrModifyCloudLogs("disable-or-modify-cloud-logs"))
            if technique['technique'] == 'Safe Mode Boot':
                techniques.append(ot.SafeModeBoot("safe-mode-boot"))
            if technique['technique'] == 'Downgrade Attack':
                techniques.append(ot.DowngradeAttack("downgrade-attack"))
            if technique['technique'] == 'Spoof Security Alerting':
                techniques.append(ot.SpoofSecurityAlerting("spoof-security-alerting"))
            if technique['technique'] == 'Disable or Modify Linux Audit System':
                techniques.append(ot.DisableOrModifyLinuxAuditSystem("disable-or-modify-linux-audit-system"))
            if technique['technique'] == 'Disable or Modify Network Device Firewall':
                techniques.append(ot.DisableOrModifyNetworkDeviceFirewall("disable-or-modify-network-device-firewall"))
            if technique['technique'] == 'Hidden Files and Directories':
                techniques.append(ot.HiddenFilesAndDirectories("hidden-files-and-directories"))
            if technique['technique'] == 'Hidden Users':
                techniques.append(ot.HiddenUsers("hidden-users"))
            if technique['technique'] == 'Run Virtual Instance':
                techniques.append(ot.RunVirtualInstance("run-virtual-instance"))
            if technique['technique'] == 'VBA Stomping':
                techniques.append(ot.VBAStomping("vba-stomping"))
            if technique['technique'] == 'Email Hiding Rules':
                techniques.append(ot.EmailHidingRules("email-hiding-rules"))
            if technique['technique'] == 'Resource Forking':
                techniques.append(ot.ResourceForking("resource-forking"))
            if technique['technique'] == 'Process Argument Spoofing':
                techniques.append(ot.ProcessArgumentSpoofing("process-argument-spoofing"))
            if technique['technique'] == 'Ignore Process Interrupts':
                techniques.append(ot.IgnoreProcessInterrupts("ignore-process-interrupts"))
            if technique['technique'] == 'File/Path Exclusions':
                techniques.append(ot.FilePathExclusions("file-path-exclusions"))
            if technique['technique'] == 'Extended Attributes':
                techniques.append(ot.ExtendedAttributes("extended-attributes"))
            if technique['technique'] == 'Protocol Tunneling':
                techniques.append(ot.ProtocolTunneling("protocol-tunneling"))
            if technique['technique'] == 'Modify Cloud Compute Infrastructure':
                techniques.append(ot.ModifyCloudComputeInfrastructure("modify-cloud-compute-infrastructure"))
            if technique['technique'] == 'Create Snapshot':
                techniques.append(ot.CreateSnapshot("create-snapshot"))
            if technique['technique'] == 'Create Cloud Instance':
                techniques.append(ot.CreateCloudInstance("create-cloud-instance"))
            if technique['technique'] == 'Delete Cloud Instance':
                techniques.append(ot.DeleteCloudInstance("delete-cloud-instance"))
            if technique['technique'] == 'Revert Cloud Instance':
                techniques.append(ot.RevertCloudInstance("revert-cloud-instance"))
            if technique['technique'] == 'Modify Cloud Compute Configurations':
                techniques.append(ot.ModifyCloudComputeConfigurations("modify-cloud-compute-configurations"))
            if technique['technique'] == 'Network Boundary Bridging':
                techniques.append(ot.NetworkBoundaryBridging("network-boundary-bridging"))
            if technique['technique'] == 'Network Address Translation Traversal':
                techniques.append(ot.NetworkAddressTranslationTraversal("network-address-translation-traversal"))
            if technique['technique'] == 'Modify System Image':
                techniques.append(ot.ModifySystemImage("modify-system-image"))
            if technique['technique'] == 'Patch System Image':
                techniques.append(ot.PatchSystemImage("patch-system-image"))
            if technique['technique'] == 'Downgrade System Image':
                techniques.append(ot.DowngradeSystemImage("downgrade-system-image"))
            if technique['technique'] == 'Build Image on Host':
                techniques.append(ot.BuildImageOnHost("build-image-on-host"))
            if technique['technique'] == 'Plist File Modification':
                techniques.append(ot.PlistFileModification("plist-file-modification"))
            if technique['technique'] == 'Impersonation':
                techniques.append(ot.Impersonation("impersonation"))
            if technique['technique'] == 'Hide Infrastructure':
                techniques.append(ot.HideInfrastructure("hide-infrastructure"))
            if technique['technique'] == 'Modify Cloud Resource Hierarchy':
                techniques.append(ot.ModifyCloudResourceHierarchy("modify-cloud-resource-hierarchy"))
            if technique['technique'] == 'Delay Execution':
                techniques.append(ot.DelayExecution("delay-execution"))
        
        # CREDENTIAL ACCESS
        if technique['tactic'] == 'Credential Access':
            if technique['technique'] == 'Hooking':
                techniques.append(ot.Hooking("hooking"))
            if technique['technique'] == 'Keylogging':
                techniques.append(ot.Keylogging("keylogging"))
            if technique['technique'] == 'Credential API Hooking':
                techniques.append(ot.CredentialAPIHooking("credential-api-hooking"))
            if technique['technique'] == 'Input Capture':
                techniques.append(ot.InputCapture("input-capture"))
            if technique['technique'] == 'Credentials from Password Stores':
                techniques.append(ot.CredentialsFromPasswordStores("credentials-from-password-stores"))
            if technique['technique'] == 'OS Credential Dumping':
                techniques.append(ot.OSCredentialDumping("os-credential-dumping"))
            if technique['technique'] == 'Windows Credential Manager':
                techniques.append(ot.WindowsCredentialManager("windows-credential-manager"))
            if technique['technique'] == 'Steal or Forge Kerberos Tickets':
                techniques.append(ot.StealOrForgeKerberosTickets("steal-or-forge-kerberos-tickets"))
            if technique['technique'] == 'Private Keys':
                techniques.append(ot.PrivateKeys("private-keys"))
            if technique['technique'] == 'Replication Through Removable Media':
                techniques.append(ot.ReplicationThroughRemovableMedia("replication-through-removable-media"))
            if technique['technique'] == 'Credentials from Web Browsers':
                techniques.append(ot.CredentialsFromWebBrowsers("credentials-from-web-browsers"))
            if technique['technique'] == 'Credentials in Registry':
                techniques.append(ot.CredentialsInRegistry("credentials-in-registry"))
            if technique['technique'] == 'Network Sniffing':
                techniques.append(ot.NetworkSniffing("network-sniffing"))
            if technique['technique'] == 'Credentials In Files':
                techniques.append(ot.CredentialsInFiles("credentials-in-files"))
            if technique['technique'] == 'Steal Web Session Cookie':
                techniques.append(ot.StealWebSessionCookie("steal-web-session-cookie"))
            if technique['technique'] == 'Password Managers':
                techniques.append(ot.PasswordManagers("password-managers"))
            if technique['technique'] == 'Unsecured Credentials':
                techniques.append(ot.UnsecuredCredentials("unsecured-credentials"))
            if technique['technique'] == 'LSASS Memory':
                techniques.append(ot.LSASSMemory("lsass-memory"))
            if technique['technique'] == 'Security Account Manager':
                techniques.append(ot.SecurityAccountManager("security-account-manager"))
            if technique['technique'] == 'NTDS':
                techniques.append(ot.NTDS("ntds"))
            if technique['technique'] == 'LSA Secrets':
                techniques.append(ot.LSASecrets("lsa-secrets"))
            if technique['technique'] == 'Cached Domain Credentials':
                techniques.append(ot.CachedDomainCredentials("cached-domain-credentials"))
            if technique['technique'] == 'DCSync':
                techniques.append(ot.DCSync("dcsync"))
            if technique['technique'] == 'Proc Filesystem':
                techniques.append(ot.ProcFilesystem("proc-filesystem"))
            if technique['technique'] == 'etc/passwd and etc/shadow':
                techniques.append(ot.EtcPasswdAndEtcShadow("etc-passwd-and-etc-shadow"))
            if technique['technique'] == 'GUI Input Capture':
                techniques.append(ot.GUIInputCapture("gui-input-capture"))
            if technique['technique'] == 'Web Portal Capture':
                techniques.append(ot.WebPortalCapture("web-portal-capture"))
            if technique['technique'] == 'Brute Force':
                techniques.append(ot.BruteForce("brute-force"))
            if technique['technique'] == 'Password Guessing':
                techniques.append(ot.PasswordGuessing("password-guessing"))
            if technique['technique'] == 'Password Cracking':
                techniques.append(ot.PasswordCracking("password-cracking"))
            if technique['technique'] == 'Password Spraying':
                techniques.append(ot.PasswordSpraying("password-spraying"))
            if technique['technique'] == 'Credential Stuffing':
                techniques.append(ot.CredentialStuffing("credential-stuffing"))
            if technique['technique'] == 'Multi-Factor Authentication Interception':
                techniques.append(ot.MultiFactorAuthenticationInterception("multi-factor-authentication-interception"))
            if technique['technique'] == 'Forced Authentication':
                techniques.append(ot.ForcedAuthentication("forced-authentication"))
            if technique['technique'] == 'Exploitation for Credential Access':
                techniques.append(ot.ExploitationForCredentialAccess("exploitation-for-credential-access"))
            if technique['technique'] == 'Steal Application Access Token':
                techniques.append(ot.StealApplicationAccessToken("steal-application-access-token"))
            if technique['technique'] == 'Shell History':
                techniques.append(ot.ShellHistory("shell-history"))
            if technique['technique'] == 'Cloud Instance Metadata API':
                techniques.append(ot.CloudInstanceMetadataAPI("cloud-instance-metadata-api"))
            if technique['technique'] == 'Group Policy Preferences':
                techniques.append(ot.GroupPolicyPreferences("group-policy-preferences"))
            if technique['technique'] == 'Container API':
                techniques.append(ot.ContainerAPI("container-api"))
            if technique['technique'] == 'Chat Messages':
                techniques.append(ot.ChatMessages("chat-messages"))
            if technique['technique'] == 'Keychain':
                techniques.append(ot.Keychain("keychain"))
            if technique['technique'] == 'Securityd Memory':
                techniques.append(ot.SecuritydMemory("securityd-memory"))
            if technique['technique'] == 'Cloud Secrets Management Stores':
                techniques.append(ot.CloudSecretsManagementStores("cloud-secrets-management-stores"))
            if technique['technique'] == 'Vaulted Credentials':
                techniques.append(ot.VaultedCredentials("vaulted-credentials"))
            if technique['technique'] == 'Adversary-in-the-Middle':
                techniques.append(ot.AdversaryInTheMiddle("adversary-in-the-middle"))
            if technique['technique'] == 'LLMNR/NBT-NS Poisoning and SMB Relay':
                techniques.append(ot.LLMNRNBTNSPoisoningAndSMBRelay("llmnr-nbt-ns-poisoning-and-smb-relay"))
            if technique['technique'] == 'ARP Cache Poisoning':
                techniques.append(ot.ARPCachePoisoning("arp-cache-poisoning"))
            if technique['technique'] == 'DHCP Spoofing':
                techniques.append(ot.DHCPSpoofing("dhcp-spoofing"))
            if technique['technique'] == 'Evil Twin':
                techniques.append(ot.EvilTwin("evil-twin"))
            if technique['technique'] == 'Golden Ticket':
                techniques.append(ot.GoldenTicket("golden-ticket"))
            if technique['technique'] == 'Silver Ticket':
                techniques.append(ot.SilverTicket("silver-ticket"))
            if technique['technique'] == 'Kerberoasting':
                techniques.append(ot.Kerberoasting("kerberoasting"))
            if technique['technique'] == 'AS-REP Roasting':
                techniques.append(ot.ASREPRoasting("as-rep-roasting"))
            if technique['technique'] == 'Forge Web Credentials':
                techniques.append(ot.ForgeWebCredentials("forge-web-credentials"))
            if technique['technique'] == 'Web Cookies':
                techniques.append(ot.WebCookies("web-cookies"))
            if technique['technique'] == 'SAML Tokens':
                techniques.append(ot.SAMLTokens("saml-tokens"))
            if technique['technique'] == 'Multi-Factor Authentication Request Generation':
                techniques.append(ot.MultiFactorAuthenticationRequestGeneration("multi-factor-authentication-request-generation"))
            if technique['technique'] == 'Steal or Forge Authentication Certificates':
                techniques.append(ot.StealOrForgeAuthenticationCertificates("steal-or-forge-authentication-certificates"))

        # DISCOVERY
        if technique['tactic'] == 'Discovery':
            if technique['technique'] == 'Query Registry':
                techniques.append(ot.QueryRegistry("query-registry"))
            if technique['technique'] == 'System Time Discovery':
                techniques.append(ot.SystemTimeDiscovery("system-time-discovery"))
            if technique['technique'] == 'System Information Discovery':
                techniques.append(ot.SystemInformationDiscovery("system-information-discovery"))
            if technique['technique'] == 'Application Window Discovery':
                techniques.append(ot.ApplicationWindowDiscovery("application-window-discovery"))
            if technique['technique'] == 'File and Directory Discovery':
                techniques.append(ot.FileAndDirectoryDiscovery("file-and-directory-discovery"))
            if technique['technique'] == 'Process Discovery':
                techniques.append(ot.ProcessDiscovery("process-discovery"))
            if technique['technique'] == 'Virtualization/Sandbox Evasion':
                techniques.append(ot.VirtualizationSandboxEvasion("virtualization-sandbox-evasion"))
            if technique['technique'] == 'System Language Discovery':
                techniques.append(ot.SystemLanguageDiscovery("system-language-discovery"))
            if technique['technique'] == 'Peripheral Device Discovery':
                techniques.append(ot.PeripheralDeviceDiscovery("peripheral-device-discovery"))
            if technique['technique'] == 'Debugger Evasion':
                techniques.append(ot.DebuggerEvasion("debugger-evasion"))
            if technique['technique'] == 'Time Based Evasion':
                techniques.append(ot.TimeBasedEvasion("time-based-evasion"))
            if technique['technique'] == 'System Location Discovery':
                techniques.append(ot.SystemLocationDiscovery("system-location-discovery"))
            if technique['technique'] == 'System Owner/User Discovery':
                techniques.append(ot.SystemOwnerUserDiscovery("system-owner-user-discovery"))
            if technique['technique'] == 'System Service Discovery':
                techniques.append(ot.SystemServiceDiscovery("system-service-discovery"))
            if technique['technique'] == 'User Activity Based Checks':
                techniques.append(ot.UserActivityBasedChecks("user-activity-based-checks"))
            if technique['technique'] == 'System Network Configuration Discovery':
                techniques.append(ot.SystemNetworkConfigurationDiscovery("system-network-configuration-discovery"))
            if technique['technique'] == 'Software Discovery':
                techniques.append(ot.SoftwareDiscovery("software-discovery"))
            if technique['technique'] == 'Network Share Discovery':
                techniques.append(ot.NetworkShareDiscovery("network-share-discovery"))
            if technique['technique'] == 'Security Software Discovery':
                techniques.append(ot.SecuritySoftwareDiscovery("security-software-discovery"))
            if technique['technique'] == 'System Checks':
                techniques.append(ot.SystemChecks("system-checks"))
            if technique['technique'] == 'Remote System Discovery':
                techniques.append(ot.RemoteSystemDiscovery("remote-system-discovery"))
            if technique['technique'] == 'Network Service Scanning':
                techniques.append(ot.NetworkServiceScanning("network-service-scanning"))
            if technique['technique'] == 'System Network Connections Discovery':
                techniques.append(ot.SystemNetworkConnectionsDiscovery("system-network-connections-discovery"))
            if technique['technique'] == 'Account Discovery':
                techniques.append(ot.AccountDiscovery("account-discovery"))
            if technique['technique'] == 'Local Account':
                techniques.append(ot.LocalAccount("local-account"))
            if technique['technique'] == 'Domain Trust Discovery':
                techniques.append(ot.DomainTrustDiscovery("domain-trust-discovery"))
            if technique['technique'] == 'Wi-Fi Discovery':
                techniques.append(ot.WiFiDiscovery("wifi-discovery"))
            if technique['technique'] == 'Internet Connection Discovery':
                techniques.append(ot.InternetConnectionDiscovery("internet-connection-discovery"))
            if technique['technique'] == 'Cloud Groups':
                techniques.append(ot.CloudGroups("cloud-groups"))
            if technique['technique'] == 'Device Driver Discovery':
                techniques.append(ot.DeviceDriverDiscovery("device-driver-discovery"))
            if technique['technique'] == 'Network Sniffing':
                techniques.append(ot.NetworkSniffing("network-sniffing"))
            if technique['technique'] == 'Log Enumeration':
                techniques.append(ot.LogEnumeration("log-enumeration"))
            if technique['technique'] == 'Browser Information Discovery':
                techniques.append(ot.BrowserInformationDiscovery("browser-information-discovery"))
            if technique['technique'] == 'Cloud Service Dashboard':
                techniques.append(ot.CloudServiceDashboard("cloud-service-dashboard"))
            if technique['technique'] == 'Domain Account':
                techniques.append(ot.DomainAccount("domain-account"))
            if technique['technique'] == 'Email Accounts':
                techniques.append(ot.EmailAccounts("email-accounts"))
            if technique['technique'] == 'Cloud Account':
                techniques.append(ot.CloudAccount("cloud-account"))
            if technique['technique'] == 'Network Service Discovery':
                techniques.append(ot.NetworkServiceDiscovery("network-service-discovery"))
            if technique['technique'] == 'Local Groups':
                techniques.append(ot.LocalGroups("local-groups"))
            if technique['technique'] == 'Domain Groups':
                techniques.append(ot.DomainGroups("domain-groups"))
            if technique['technique'] == 'Password Policy Discovery':
                techniques.append(ot.PasswordPolicyDiscovery("password-policy-discovery"))
            if technique['technique'] == 'Backup Software Discovery':
                techniques.append(ot.BackupSoftwareDiscovery("backup-software-discovery"))
            if technique['technique'] == 'Cloud Service Discovery':
                techniques.append(ot.CloudServiceDiscovery("cloud-service-discovery"))
            if technique['technique'] == 'Cloud Infrastructure Discovery':
                techniques.append(ot.CloudInfrastructureDiscovery("cloud-infrastructure-discovery"))
            if technique['technique'] == 'Container and Resource Discovery':
                techniques.append(ot.ContainerAndResourceDiscovery("container-and-resource-discovery"))
            if technique['technique'] == 'Group Policy Discovery':
                techniques.append(ot.GroupPolicyDiscovery("group-policy-discovery"))
            if technique['technique'] == 'Cloud Storage Object Discovery':
                techniques.append(ot.CloudStorageObjectDiscovery("cloud-storage-object-discovery"))
            if technique['technique'] == 'Virtual Machine Discovery':
                techniques.append(ot.VirtualMachineDiscovery("virtual-machine-discovery"))
            if technique['technique'] == 'Local Storage Discovery':
                techniques.append(ot.LocalStorageDiscovery("local-storage-discovery"))

        # LATERAL MOVEMENT
        if technique['tactic'] == 'Lateral Movement':
            if technique['technique'] == 'Remote Desktop Protocol':
                techniques.append(ot.RemoteDesktopProtocol("remote-desktop-protocol"))
            if technique['technique'] == 'Lateral Tool Transfer':
                techniques.append(ot.LateralToolTransfer("lateral-tool-transfer"))
            if technique['technique'] == 'Remote Services':
                techniques.append(ot.RemoteServices("remote-services"))
            if technique['technique'] == 'Pass the Hash':
                techniques.append(ot.PassTheHash("pass-the-hash"))
            if technique['technique'] == 'Replication Through Removable Media':
                techniques.append(ot.ReplicationThroughRemovableMedia("replication-through-removable-media"))
            if technique['technique'] == 'Software Deployment Tools':
                techniques.append(ot.SoftwareDeploymentTools("software-deployment-tools"))
            if technique['technique'] == 'VNC':
                techniques.append(ot.VNC("vnc"))
            if technique['technique'] == 'Windows Remote Management':
                techniques.append(ot.WindowsRemoteManagement("windows-remote-management"))
            if technique['technique'] == 'SMB/Windows Admin Shares':
                techniques.append(ot.SMBWindowsAdminShares("smb-windows-admin-shares"))
            if technique['technique'] == 'Distributed Component Object Model':
                techniques.append(ot.DistributedComponentObjectModel("distributed-component-object-model"))
            if technique['technique'] == 'SSH':
                techniques.append(ot.SSH("ssh"))
            if technique['technique'] == 'Cloud Services':
                techniques.append(ot.CloudServices("cloud-services"))
            if technique['technique'] == 'Direct Cloud VM Connections':
                techniques.append(ot.DirectCloudVMConnections("direct-cloud-vm-connections"))
            if technique['technique'] == 'Taint Shared Content':
                techniques.append(ot.TaintSharedContent("taint-shared-content"))
            if technique['technique'] == 'Exploitation of Remote Services':
                techniques.append(ot.ExploitationOfRemoteServices("exploitation-of-remote-services"))
            if technique['technique'] == 'Internal Spearphishing':
                techniques.append(ot.InternalSpearphishing("internal-spearphishing"))
            if technique['technique'] == 'Remote Service Session Hijacking':
                techniques.append(ot.RemoteServiceSessionHijacking("remote-service-session-hijacking"))
            if technique['technique'] == 'SSH Hijacking':
                techniques.append(ot.SSHHijacking("ssh-hijacking"))
            if technique['technique'] == 'RDP Hijacking':
                techniques.append(ot.RDPHijacking("rdp-hijacking"))
        
        # COLLECTION
        if technique['tactic'] == 'Collection':
            if technique['technique'] == 'Email Collection':
                techniques.append(ot.EmailCollection("email-collection"))
            if technique['technique'] == 'Screen Capture':
                techniques.append(ot.ScreenCapture("screen-capture"))
            if technique['technique'] == 'Keylogging':
                techniques.append(ot.Keylogging("keylogging"))
            if technique['technique'] == 'Local Data Staging':
                techniques.append(ot.LocalDataStaging("local-data-staging"))
            if technique['technique'] == 'Credential API Hooking':
                techniques.append(ot.CredentialAPIHooking("credential-api-hooking"))
            if technique['technique'] == 'Clipboard Data':
                techniques.append(ot.ClipboardData("clipboard-data"))
            if technique['technique'] == 'Data from Local System':
                techniques.append(ot.DataFromLocalSystem("data-from-local-system"))
            if technique['technique'] == 'Input Capture':
                techniques.append(ot.InputCapture("input-capture"))
            if technique['technique'] == 'Data from Information Repositories':
                techniques.append(ot.DataFromInformationRepositories("data-from-information-repositories"))
            if technique['technique'] == 'Automated Collection':
                techniques.append(ot.AutomatedCollection("automated-collection"))
            if technique['technique'] == 'Archive via Library':
                techniques.append(ot.ArchiveViaLibrary("archive-via-library"))
            if technique['technique'] == 'Archive Collected Data':
                techniques.append(ot.ArchiveCollectedData("archive-collected-data"))
            if technique['technique'] == 'Local Email Collection':
                techniques.append(ot.LocalEmailCollection("local-email-collection"))
            if technique['technique'] == 'Data from Removable Media':
                techniques.append(ot.DataFromRemovableMedia("data-from-removable-media"))
            if technique['technique'] == 'Remote Email Collection':
                techniques.append(ot.RemoteEmailCollection("remote-email-collection"))
            if technique['technique'] == 'Archive via Utility':
                techniques.append(ot.ArchiveViaUtility("archive-via-utility"))
            if technique['technique'] == 'Data Staged':
                techniques.append(ot.DataStaged("data-staged"))
            if technique['technique'] == 'Sharepoint':
                techniques.append(ot.Sharepoint("sharepoint"))
            if technique['technique'] == 'Data from Network Shared Drive':
                techniques.append(ot.DataFromNetworkSharedDrive("data-from-network-shared-drive"))
            if technique['technique'] == 'Remote Data Staging':
                techniques.append(ot.RemoteDataStaging("remote-data-staging"))
            if technique['technique'] == 'Email Forwarding Rule':
                techniques.append(ot.EmailForwardingRule("email-forwarding-rule"))
            if technique['technique'] == 'Audio Capture':
                techniques.append(ot.AudioCapture("audio-capture"))
            if technique['technique'] == 'Video Capture':
                techniques.append(ot.VideoCapture("video-capture"))
            if technique['technique'] == 'Browser Session Hijacking':
                techniques.append(ot.BrowserSessionHijacking("browser-session-hijacking"))
            if technique['technique'] == 'Confluence':
                techniques.append(ot.Confluence("confluence"))
            if technique['technique'] == 'Code Repositories':
                techniques.append(ot.CodeRepositories("code-repositories"))
            if technique['technique'] == 'Customer Relationship Management Software':
                techniques.append(ot.CustomerRelationshipManagementSoftware("customer-relationship-management-software"))
            if technique['technique'] == 'Messaging Applications':
                techniques.append(ot.MessagingApplications("messaging-applications"))
            if technique['technique'] == 'Databases':
                techniques.append(ot.Databases("databases"))
            if technique['technique'] == 'Data from Cloud Storage':
                techniques.append(ot.DataFromCloudStorage("data-from-cloud-storage"))
            if technique['technique'] == 'Archive via Custom Method':
                techniques.append(ot.ArchiveViaCustomMethod("archive-via-custom-method"))
            if technique['technique'] == 'Data from Configuration Repository':
                techniques.append(ot.DataFromConfigurationRepository("data-from-configuration-repository"))
            if technique['technique'] == 'Network Device Configuration Dump':
                techniques.append(ot.NetworkDeviceConfigurationDump("network-device-configuration-dump"))

        # COMMAND AND CONTROL
        if technique['tactic'] == 'Command and Control':
            if technique['technique'] == 'Encrypted Channel':
                techniques.append(ot.EncryptedChannel("encrypted-channel"))
            if technique['technique'] == 'Ingress Tool Transfer':
                techniques.append(ot.IngressToolTransfer("ingress-tool-transfer"))
            if technique['technique'] == 'Application Layer Protocol':
                techniques.append(ot.ApplicationLayerProtocol("application-layer-protocol"))
            if technique['technique'] == 'Symmetric Cryptography':
                techniques.append(ot.SymmetricCryptography("symmetric-cryptography"))
            if technique['technique'] == 'Web Protocols':
                techniques.append(ot.WebProtocols("web-protocols"))
            if technique['technique'] == 'Non-Application Layer Protocol':
                techniques.append(ot.NonApplicationLayerProtocol("non-application-layer-protocol"))
            if technique['technique'] == 'Non-Standard Port':
                techniques.append(ot.NonStandardPort("non-standard-port"))
            if technique['technique'] == 'Data Encoding':
                techniques.append(ot.DataEncoding("data-encoding"))
            if technique['technique'] == 'Proxy':
                techniques.append(ot.Proxy("proxy"))
            if technique['technique'] == 'Mail Protocols':
                techniques.append(ot.MailProtocols("mail-protocols"))
            if technique['technique'] == 'Asymmetric Cryptography':
                techniques.append(ot.AsymmetricCryptography("asymmetric-cryptography"))
            if technique['technique'] == 'DNS':
                techniques.append(ot.DNS("dns"))
            if technique['technique'] == 'Commonly Used Port':
                techniques.append(ot.CommonlyUsedPort("commonly-used-port"))
            if technique['technique'] == 'Custom Command and Control Protocol':
                techniques.append(ot.CustomCommandAndControlProtocol("custom-command-and-control-protocol"))
            if technique['technique'] == 'Standard Encoding':
                techniques.append(ot.StandardEncoding("standard-encoding"))
            if technique['technique'] == 'Web Service':
                techniques.append(ot.WebService("web-service"))
            if technique['technique'] == 'Socket Filters':
                techniques.append(ot.SocketFilters("socket-filters"))
            if technique['technique'] == 'Steganography':
                techniques.append(ot.Steganography("steganography"))
            if technique['technique'] == 'Domain Generation Algorithms':
                techniques.append(ot.DomainGenerationAlgorithms("domain-generation-algorithms"))
            if technique['technique'] == 'Internal Proxy':
                techniques.append(ot.InternalProxy("internal-proxy"))
            if technique['technique'] == 'Uncommonly Used Port':
                techniques.append(ot.NonStandardPort("non-standard-port"))
            if technique['technique'] == 'Remote Access Tools':
                techniques.append(ot.RemoteAccessTools("remote-access-tools"))
            if technique['technique'] == 'Remote Desktop Software':
                techniques.append(ot.RemoteDesktopSoftware("remote-desktop-software"))
            if technique['technique'] == 'Dead Drop Resolver':
                techniques.append(ot.DeadDropResolver("dead-drop-resolver"))
            if technique['technique'] == 'One-Way Communication':
                techniques.append(ot.OneWayCommunication("one-way-communication"))
            if technique['technique'] == 'Multi-hop Proxy':
                techniques.append(ot.MultiHopProxy("multi-hop-proxy"))
            if technique['technique'] == 'Bidirectional Communication':
                techniques.append(ot.BidirectionalCommunication("bidirectional-communication"))
            if technique['technique'] == 'File Transfer Protocols':
                techniques.append(ot.FileTransferProtocols("file-transfer-protocols"))
            if technique['technique'] == 'Junk Data':
                techniques.append(ot.JunkData("junk-data"))
            if technique['technique'] == 'Protocol or Service Impersonation':
                techniques.append(ot.ProtocolOrServiceImpersonation("protocol-or-service-impersonation"))
            if technique['technique'] == 'Fallback Channels':
                techniques.append(ot.FallbackChannels("fallback-channels"))
            if technique['technique'] == 'Publish/Subscribe Protocols':
                techniques.append(ot.PublishSubscribeProtocols("publish-subscribe-protocols"))
            if technique['technique'] == 'Communication Through Removable Media':
                techniques.append(ot.CommunicationThroughRemovableMedia("communication-through-removable-media"))
            if technique['technique'] == 'Multi-Stage Channels':
                techniques.append(ot.MultiStageChannels("multi-stage-channels"))
            if technique['technique'] == 'IDE Tunneling':
                techniques.append(ot.IDETunneling("ide-tunneling"))
            if technique['technique'] == 'Remote Access Hardware':
                techniques.append(ot.RemoteAccessHardware("remote-access-hardware"))
            if technique['technique'] == 'Fast Flux DNS':
                techniques.append(ot.FastFluxDNS("fast-flux-dns"))
            if technique['technique'] == 'DNS Calculation':
                techniques.append(ot.DNSCalculation("dns-calculation"))
            
        # EXFILTRATION
        if technique['tactic'] == 'Exfiltration':
            if technique['technique'] == 'Data Compressed':
                techniques.append(ot.DataCompressed("data-compressed"))
            if technique['technique'] == 'Scheduled Transfer':
                techniques.append(ot.ScheduledTransfer("scheduled-transfer"))
            if technique['technique'] == 'Exfiltration Over Other Network Medium':
                techniques.append(ot.ExfiltrationOverOtherNetworkMedium("exfiltration-over-other-network-medium"))
            if technique['technique'] == 'Exfiltration Over C2 Channel':
                techniques.append(ot.ExfiltrationOverC2Channel("exfiltration-over-c2-channel"))
            if technique['technique'] == 'Exfiltration Over Web Service':
                techniques.append(ot.ExfiltrationOverWebService("exfiltration-over-web-service"))
            if technique['technique'] == 'Data Transfer Size Limits':
                techniques.append(ot.DataTransferSizeLimits("data-transfer-size-limits"))
            if technique['technique'] == 'Exfiltration Over Asymmetric Encrypted Non-C2 Protocol':
                techniques.append(ot.ExfiltrationOverAsymmetricEncryptedNonC2Protocol("exfiltration-over-asymmetric-encrypted-non-c2-protocol"))
            if technique['technique'] == 'Exfiltration to Text Storage Sites':
                techniques.append(ot.ExfiltrationToTextStorageSites("exfiltration-to-text-storage-sites"))
            if technique['technique'] == 'Exfiltration Over Alternative Protocol':
                techniques.append(ot.ExfiltrationOverAlternativeProtocol("exfiltration-over-alternative-protocol"))
            if technique['technique'] == 'Exfiltration Over Unencrypted Non-C2 Protocol':
                techniques.append(ot.ExfiltrationOverUnencryptedNonC2Protocol("exfiltration-over-unencrypted-non-c2-protocol"))
            if technique['technique'] == 'Exfiltration Over Bluetooth':
                techniques.append(ot.ExfiltrationOverBluetooth("exfiltration-over-bluetooth"))
            if technique['technique'] == 'Automated Exfiltration':
                techniques.append(ot.AutomatedExfiltration("automated-exfiltration"))
            if technique['technique'] == 'Traffic Duplication':
                techniques.append(ot.TrafficDuplication("traffic-duplication"))
            if technique['technique'] == 'Exfiltration Over Symmetric Encrypted Non-C2 Protocol':
                techniques.append(ot.ExfiltrationOverSymmetricEncryptedNonC2Protocol("exfiltration-over-symmetric-encrypted-non-c2-protocol"))
            if technique['technique'] == 'Exfiltration Over Physical Medium':
                techniques.append(ot.ExfiltrationOverPhysicalMedium("exfiltration-over-physical-medium"))
            if technique['technique'] == 'Exfiltration over USB':
                techniques.append(ot.ExfiltrationOverUSB("exfiltration-over-usb"))
            if technique['technique'] == 'Transfer Data to Cloud Account':
                techniques.append(ot.TransferDataToCloudAccount("transfer-data-to-cloud-account"))
            if technique['technique'] == 'Exfiltration to Code Repository':
                techniques.append(ot.ExfiltrationToCodeRepository("exfiltration-to-code-repository"))
            if technique['technique'] == 'Exfiltration to Cloud Storage':
                techniques.append(ot.ExfiltrationToCloudStorage("exfiltration-to-cloud-storage"))
            if technique['technique'] == 'Exfiltration Over Webhook':
                techniques.append(ot.ExfiltrationOverWebhook("exfiltration-over-webhook"))

        # IMPACT
        if technique['tactic'] == 'Impact':
            if technique['technique'] == 'Service Stop':
                techniques.append(ot.ServiceStop("service-stop"))
            if technique['technique'] == 'System Shutdown/Reboot':
                techniques.append(ot.SystemShutdownReboot("system-shutdown-reboot"))
            if technique['technique'] == 'Data Encrypted for Impact':
                techniques.append(ot.DataEncryptedForImpact("data-encrypted-for-impact"))
            if technique['technique'] == 'Data Destruction':
                techniques.append(ot.DataDestruction("data-destruction"))
            if technique['technique'] == 'Disk Content Wipe':
                techniques.append(ot.DiskContentWipe("disk-content-wipe"))
            if technique['technique'] == 'Internal Defacement':
                techniques.append(ot.InternalDefacement("internal-defacement"))
            if technique['technique'] == 'Data Manipulation':
                techniques.append(ot.DataManipulation("data-manipulation"))
            if technique['technique'] == 'Endpoint Denial of Service':
                techniques.append(ot.EndpointDenialOfService("endpoint-denial-of-service"))
            if technique['technique'] == 'Account Access Removal':
                techniques.append(ot.AccountAccessRemoval("account-access-removal"))
            if technique['technique'] == 'Defacement':
                techniques.append(ot.Defacement("defacement"))
            if technique['technique'] == 'Inhibit System Recovery':
                techniques.append(ot.InhibitSystemRecovery("inhibit-system-recovery"))
            if technique['technique'] == 'External Defacement':
                techniques.append(ot.ExternalDefacement("external-defacement"))
            if technique['technique'] == 'Firmware Corruption':
                techniques.append(ot.FirmwareCorruption("firmware-corruption"))
            if technique['technique'] == 'Resource Hijacking':
                techniques.append(ot.ResourceHijacking("resource-hijacking"))
            if technique['technique'] == 'Compute Hijacking':
                techniques.append(ot.ComputeHijacking("compute-hijacking"))
            if technique['technique'] == 'Bandwidth Hijacking':
                techniques.append(ot.BandwidthHijacking("bandwidth-hijacking"))
            if technique['technique'] == 'SMS Pumping':
                techniques.append(ot.SMSPumping("sms-pumping"))
            if technique['technique'] == 'Cloud Service Hijacking':
                techniques.append(ot.CloudServiceHijacking("cloud-service-hijacking"))
            if technique['technique'] == 'Network Denial of Service':
                techniques.append(ot.NetworkDenialOfService("network-denial-of-service"))
            if technique['technique'] == 'Direct Network Flood':
                techniques.append(ot.DirectNetworkFlood("direct-network-flood"))
            if technique['technique'] == 'Reflection Amplification':
                techniques.append(ot.ReflectionAmplification("reflection-amplification"))
            if technique['technique'] == 'OS Exhaustion Flood':
                techniques.append(ot.OSExhaustionFlood("os-exhaustion-flood"))
            if technique['technique'] == 'Service Exhaustion Flood':
                techniques.append(ot.ServiceExhaustionFlood("service-exhaustion-flood"))
            if technique['technique'] == 'Application Exhaustion Flood':
                techniques.append(ot.ApplicationExhaustionFlood("application-exhaustion-flood"))
            if technique['technique'] == 'Application or System Exploitation':
                techniques.append(ot.ApplicationOrSystemExploitation("application-or-system-exploitation"))
            if technique['technique'] == 'Disk Wipe':
                techniques.append(ot.DiskWipe("disk-wipe"))
            if technique['technique'] == 'Disk Structure Wipe':
                techniques.append(ot.DiskStructureWipe("disk-structure-wipe"))
            if technique['technique'] == 'Stored Data Manipulation':
                techniques.append(ot.StoredDataManipulation("stored-data-manipulation"))
            if technique['technique'] == 'Transmitted Data Manipulation':
                techniques.append(ot.TransmittedDataManipulation("transmitted-data-manipulation"))
            if technique['technique'] == 'Runtime Data Manipulation':
                techniques.append(ot.RuntimeDataManipulation("runtime-data-manipulation"))
            if technique['technique'] == 'Financial Theft':
                techniques.append(ot.FinancialTheft("financial-theft"))
            if technique['technique'] == 'Email Bombing':
                techniques.append(ot.EmailBombing("email-bombing"))
            
        # INITIAL ACCESS
        if technique['tactic'] == 'Initial Access':
            if technique['technique'] == 'Drive-by Compromise':
                techniques.append(ot.DriveByCompromise("drive-by-compromise"))
            if technique['technique'] == 'Exploit Public-Facing Application':
                techniques.append(ot.ExploitPublicFacingApplication("exploit-public-facing-application"))
            if technique['technique'] == 'Phishing':
                techniques.append(ot.Phishing("phishing"))
            if technique['technique'] == 'Valid Accounts':
                techniques.append(ot.ValidAccounts("valid-accounts"))
            if technique['technique'] == 'Supply Chain Compromise':
                techniques.append(ot.SupplyChainCompromise("supply-chain-compromise"))
            if technique['technique'] == 'Trusted Relationship':
                techniques.append(ot.TrustedRelationship("trusted-relationship"))
            if technique['technique'] == 'Replication Through Removable Media':
                techniques.append(ot.ReplicationThroughRemovableMedia("replication-through-removable-media"))
            if technique['technique'] == 'Hardware Additions':
                techniques.append(ot.HardwareAdditions("hardware-additions"))
            if technique['technique'] == 'Spearphishing Attachment':
                techniques.append(ot.SpearphishingAttachment("spearphishing-attachment"))
            if technique['technique'] == 'Spearphishing Link':
                techniques.append(ot.SpearphishingLink("spearphishing-link"))
            if technique['technique'] == 'Spearphishing via Service':
                techniques.append(ot.SpearphishingViaService("spearphishing-via-service"))
            if technique['technique'] == 'Default Accounts':
                techniques.append(ot.DefaultAccounts("default-accounts"))
            if technique['technique'] == 'Domain Accounts':
                techniques.append(ot.DomainAccounts("domain-accounts"))
            if technique['technique'] == 'Local Accounts':
                techniques.append(ot.LocalAccounts("local-accounts"))
            if technique['technique'] == 'Cloud Accounts':
                techniques.append(ot.CloudAccounts("cloud-accounts"))
            if technique['technique'] == 'External Remote Services':
                techniques.append(ot.ExternalRemoteServices("external-remote-services"))
            if technique['technique'] == 'Compromise Software Dependencies and Development Tools':
                techniques.append(ot.CompromiseSoftwareDependenciesAndDevelopmentTools("compromise-software-dependencies-and-development-tools"))
            if technique['technique'] == 'Compromise Software Supply Chain':
                techniques.append(ot.CompromiseSoftwareSupplyChain("compromise-software-supply-chain"))
            if technique['technique'] == 'Compromise Hardware Supply Chain':
                techniques.append(ot.CompromiseHardwareSupplyChain("compromise-hardware-supply-chain"))
            if technique['technique'] == 'Spearphishing Voice':
                techniques.append(ot.SpearphishingVoice("spearphishing-voice"))
            if technique['technique'] == 'Content Injection':
                techniques.append(ot.ContentInjection("content-injection"))
            if technique['technique'] == 'Wi-Fi Networks':
                techniques.append(ot.WiFiNetworks("wifi-networks"))
        
        # RECONNAISSANCE
        if technique['tactic'] == 'Reconnaissance':
            if technique['technique'] == 'Search Open Websites/Domains':
                techniques.append(ot.SearchOpenWebsitesDomains("search-open-websites-domains"))
            if technique['technique'] == 'Gather Victim Identity Information':
                techniques.append(ot.GatherVictimIdentityInformation("gather-victim-identity-information"))
            if technique['technique'] == 'Gather Victim Network Information':
                techniques.append(ot.GatherVictimNetworkInformation("gather-victim-network-information"))
            if technique['technique'] == 'Gather Victim Org Information':
                techniques.append(ot.GatherVictimOrgInformation("gather-victim-org-information"))
            if technique['technique'] == 'Phishing for Information':
                techniques.append(ot.PhishingForInformation("phishing-for-information"))
            if technique['technique'] == 'Search Victim-Owned Websites':
                techniques.append(ot.SearchVictimOwnedWebsites("search-victim-owned-websites"))
            if technique['technique'] == 'Social Media Accounts':
                techniques.append(ot.SocialMediaAccounts("social-media-accounts"))
            if technique['technique'] == 'Email Addresses':
                techniques.append(ot.EmailAddresses("email-addresses"))
            if technique['technique'] == 'Employee Names':
                techniques.append(ot.EmployeeNames("employee-names"))
            if technique['technique'] == 'Phone Numbers':
                techniques.append(ot.PhoneNumbers("phone-numbers"))
            if technique['technique'] == 'Physical Addresses':
                techniques.append(ot.PhysicalAddresses("physical-addresses"))
            if technique['technique'] == 'IP Addresses':
                techniques.append(ot.IPAddresses("ip-addresses"))
            if technique['technique'] == 'Domain Properties':
                techniques.append(ot.DomainProperties("domain-properties"))
            if technique['technique'] == 'Network Trust Dependencies':
                techniques.append(ot.NetworkTrustDependencies("network-trust-dependencies"))
            if technique['technique'] == 'Network Topology':
                techniques.append(ot.NetworkTopology("network-topology"))
            if technique['technique'] == 'Network Security Appliances':
                techniques.append(ot.NetworkSecurityAppliances("network-security-appliances"))
            if technique['technique'] == 'Determine Physical Locations':
                techniques.append(ot.DeterminePhysicalLocations("determine-physical-locations"))
            if technique['technique'] == 'Business Relationships':
                techniques.append(ot.BusinessRelationships("business-relationships"))
            if technique['technique'] == 'Identify Business Tempo':
                techniques.append(ot.IdentifyBusinessTempo("identify-business-tempo"))
            if technique['technique'] == 'Identify Roles':
                techniques.append(ot.IdentifyRoles("identify-roles"))
            if technique['technique'] == 'Gather Victim Host Information':
                techniques.append(ot.GatherVictimHostInformation("gather-victim-host-information"))
            if technique['technique'] == 'Hardware':
                techniques.append(ot.Hardware("hardware"))
            if technique['technique'] == 'Software':
                techniques.append(ot.Software("software"))
            if technique['technique'] == 'Firmware':
                techniques.append(ot.Firmware("firmware"))
            if technique['technique'] == 'Client Configurations':
                techniques.append(ot.ClientConfigurations("client-configurations"))
            if technique['technique'] == 'Social Media':
                techniques.append(ot.SocialMedia("social-media"))
            if technique['technique'] == 'Search Engines':
                techniques.append(ot.SearchEngines("search-engines"))
            if technique['technique'] == 'Active Scanning':
                techniques.append(ot.ActiveScanning("active-scanning"))
            if technique['technique'] == 'Scanning IP Blocks':
                techniques.append(ot.ScanningIPBlocks("scanning-ip-blocks"))
            if technique['technique'] == 'Vulnerability Scanning':
                techniques.append(ot.VulnerabilityScanning("vulnerability-scanning"))
            if technique['technique'] == 'Wordlist Scanning':
                techniques.append(ot.WordlistScanning("wordlist-scanning"))
            if technique['technique'] == 'Search Open Technical Databases':
                techniques.append(ot.SearchOpenTechnicalDatabases("search-open-technical-databases"))
            if technique['technique'] == 'DNS/Passive DNS':
                techniques.append(ot.DNSPassiveDNS("dns-passive-dns"))
            if technique['technique'] == 'WHOIS':
                techniques.append(ot.WHOIS("whois"))
            if technique['technique'] == 'CDNs':
                techniques.append(ot.CDNs("cdns"))
            if technique['technique'] == 'Scan Databases':
                techniques.append(ot.ScanDatabases("scan-databases"))
            if technique['technique'] == 'Search Closed Sources':
                techniques.append(ot.SearchClosedSources("search-closed-sources"))
            if technique['technique'] == 'Threat Intel Vendors':
                techniques.append(ot.ThreatIntelVendors("threat-intel-vendors"))
            if technique['technique'] == 'Purchase Technical Data':
                techniques.append(ot.PurchaseTechnicalData("purchase-technical-data"))
            if technique['technique'] == 'Spearphishing Service':
                techniques.append(ot.SpearphishingService("spearphishing-service"))
            if technique['technique'] == 'Search Threat Vendor Data':
                techniques.append(ot.SearchThreatVendorData("search-threat-vendor-data"))
        
        # RESOURCE DEVELOPMENT
        if technique['tactic'] == 'Resource Development':
            if technique['technique'] == 'Acquire Infrastructure':
                techniques.append(ot.AcquireInfrastructure("acquire-infrastructure"))
            if technique['technique'] == 'Acquire Access':
                techniques.append(ot.AcquireAccess("acquire-access"))
            if technique['technique'] == 'Compromise Infrastructure':
                techniques.append(ot.CompromiseInfrastructure("compromise-infrastructure"))
            if technique['technique'] == 'Compromise Accounts':
                techniques.append(ot.CompromiseAccounts("compromise-accounts"))
            if technique['technique'] == 'Compromise Web Services':
                techniques.append(ot.CompromiseWebServices("compromise-web-services"))
            if technique['technique'] == 'Develop Capabilities':
                techniques.append(ot.DevelopCapabilities("develop-capabilities"))
            if technique['technique'] == 'Establish Accounts':
                techniques.append(ot.EstablishAccounts("establish-accounts"))
            if technique['technique'] == 'Obtain Capabilities':
                techniques.append(ot.ObtainCapabilities("obtain-capabilities"))
            if technique['technique'] == 'Stage Capabilities':
                techniques.append(ot.StageCapabilities("stage-capabilities"))
            if technique['technique'] == 'Domains':
                techniques.append(ot.Domains("domains"))
            if technique['technique'] == 'DNS Server':
                techniques.append(ot.DNSServer("dns-server"))
            if technique['technique'] == 'Virtual Private Server':
                techniques.append(ot.VirtualPrivateServer("virtual-private-server"))
            if technique['technique'] == 'Server':
                techniques.append(ot.Server("server"))
            if technique['technique'] == 'Serverless':
                techniques.append(ot.Serverless("serverless"))
            if technique['technique'] == 'Botnet':
                techniques.append(ot.Botnet("botnet"))
            if technique['technique'] == 'Web Services':
                techniques.append(ot.WebServices("web-services"))
            if technique['technique'] == 'Network Devices':
                techniques.append(ot.NetworkDevices("network-devices"))
            if technique['technique'] == 'Malware':
                techniques.append(ot.Malware("malware"))
            if technique['technique'] == 'Code Signing Certificates':
                techniques.append(ot.CodeSigningCertificates("code-signing-certificates"))
            if technique['technique'] == 'Code Signing Certificate':
                techniques.append(ot.CodeSigningCertificate("code-signing-certificate"))
            if technique['technique'] == 'Digital Certificates':
                techniques.append(ot.DigitalCertificates("digital-certificates"))
            if technique['technique'] == 'Exploits':
                techniques.append(ot.Exploits("exploits"))
            if technique['technique'] == 'Vulnerabilities':
                techniques.append(ot.Vulnerabilities("vulnerabilities"))
            if technique['technique'] == 'Tool':
                techniques.append(ot.Tool("tool"))
            if technique['technique'] == 'Artificial Intelligence':
                techniques.append(ot.ArtificialIntelligence("artificial-intelligence"))
            if technique['technique'] == 'Social Media Accounts':
                techniques.append(ot.SocialMediaAccounts("social-media-accounts"))
            if technique['technique'] == 'Email Accounts':
                techniques.append(ot.EmailAccounts("email-accounts"))
            if technique['technique'] == 'Upload Malware':
                techniques.append(ot.UploadMalware("upload-malware"))
            if technique['technique'] == 'Upload Tool':
                techniques.append(ot.UploadTool("upload-tool"))
            if technique['technique'] == 'Drive-by Target':
                techniques.append(ot.DriveByTarget("drive-by-target"))
            if technique['technique'] == 'Link Target':
                techniques.append(ot.LinkTarget("link-target"))
            if technique['technique'] == 'Install Digital Certificate':
                techniques.append(ot.InstallDigitalCertificate("install-digital-certificate"))
            if technique['technique'] == 'Install Digital Certificates':
                techniques.append(ot.InstallDigitalCertificates("install-digital-certificates"))
            if technique['technique'] == 'Malvertising':
                techniques.append(ot.Malvertising("malvertising"))
            if technique['technique'] == 'SEO Poisoning':
                techniques.append(ot.SEOPoisoning("seo-poisoning"))
            
    sample_obj.performedTechnique = techniques

def map_processes(sample, ot, sample_hash, sample_obj, path):
    process_dict = {}

    for process in sample['processes']:
        if process['name'] == '<Ignored Process>':
            continue

        process_name = process['name']

        if process_name == '<Input Sample>':
            process_name = sample_hash + "_input_sample"

        new_process_obj = ot.Process(sample_hash + "_" + process_name)
        map_actions(new_process_obj, process['name'], path, ot, process['uid'])
        map_files(new_process_obj, process['name'], path, ot, process['uid'])
        map_registry(new_process_obj, process['name'], path, ot, process['uid'])

        process_dict[process['uid']] = new_process_obj

        if process['parentuid'] is None:
            sample_obj.executedIn.append(new_process_obj)
        else:
            parentuid = process['parentuid']
            if parentuid in process_dict:
                process_dict[parentuid].hadChild.append(new_process_obj)

def map_to_ontology(malware_paths, benign_paths, ot, save_path, dataset_name):
    positive_file = open(save_path + "/" + dataset_name + "_positive.txt", "w")
    negative_file = open(save_path + "/" + dataset_name + "_negative.txt", "w")

    for path in malware_paths:
        sample_path = path + "/report.json"
        with open(sample_path) as file:
            sample = json.load(file)

        if 'md5' not in sample:
            print("[*] Sample with no MD5 hash found, skipping: ", path)
            continue
        
        sample_hash = sample['md5']
        sample_obj = ot.Sample(sample_hash)
        map_mitre(sample, ot, sample_obj)
        map_processes(sample, ot, sample_hash, sample_obj, path)
        positive_file.write("\"ex:" + sample_hash + "\",\n")
    
    for path in benign_paths:
        sample_path = path + "/report.json"
        with open(sample_path) as file:
            sample = json.load(file)
        
        sample_hash = sample['md5']
        sample_obj = ot.Sample(sample_hash)
        map_mitre(sample, ot, sample_obj)
        map_processes(sample, ot, sample_hash, sample_obj, path)
        negative_file.write("\"ex:" + sample_hash + "\",\n")
    
    positive_file.close()
    negative_file.close()

def map_ontology(ontology_path, ontology_name, malware_paths, benign_paths, save_path, dataset_name):
    ot = owlready2.get_ontology(ontology_name)
    ot.load()

    map_to_ontology(malware_paths, benign_paths, ot, save_path, dataset_name)
    path = save_path + "/" + dataset_name + ".owl"
    ot.save(file = path)

    for individual in owlready2.default_world.individuals():
        owlready2.destroy_entity(individual)

def clear_ontology(ontology_path, ontology_name):
    print("[*] Clearing ontology")
    f = open(ontology_path + "/" + ontology_name, "r")
    data = f.read()
    f.close()

    data = data.replace(u'\x02', '')
    data = data.replace(u'\x16', '')

    f = open(ontology_path + "/" + ontology_name, "w")
    f.write(data)
    f.close()

def create_ontology_dataset(path, name, malware_paths, benign_paths, dataset_name, save_path):
    map_ontology(path, name, malware_paths, benign_paths, save_path, dataset_name)
    clear_ontology(save_path, dataset_name + ".owl")

def get_all_subdirs(base_dir):
    return [
        os.path.join(base_dir, d)
        for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d))
    ]

ontology_path = "/home/peter/Desktop/dynamic/"
ontology_name = "maeco-mini.owl"
output_path = "./ontologies"

load_actions("actions.json")
load_file_regex("file_regex.json")
load_registry_regex("registry_regex.json")

malware_paths = []
benign_paths = []

malware_paths = get_all_subdirs("/home/peter/Desktop/dynamic/malware_dataset/")
benign_paths = get_all_subdirs("/home/peter/Desktop/dynamic/benign_dataset/")

create_ontology_dataset(ontology_path, ontology_name, malware_paths, benign_paths, "test", output_path)