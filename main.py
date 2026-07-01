import json
import os
import urllib
import random
import re
import csv
import argparse
import sys

from owlready2 import *

api_actions = {}
file_regex_patterns = {}
registry_regex_patterns = {}
deprecated_techniques = {}
missing_techniques = set()

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

def load_deprecated_techniques(path):
    global deprecated_techniques

    try:
        with open(path, newline="") as file:
            csvreader = csv.DictReader(file)
            for technique in csvreader:
                deprecated_techniques[technique["deprecated ID"]] = technique["replacement ID"]
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
    try:
        with open(api_call_path) as file:
            api_calls = json.load(file)
    except OSError:
        print("[*] Failed to open file: ", api_call_path)
        return
    
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
        actions.append(ot.CreateRemoteThreadInProcess("create-remote-thread-in-process"))
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
    global missing_techniques

    techniques = []

    for technique in sample["mitre_attcks"]:
        attck_id = technique['attck_id']
        if attck_id in deprecated_techniques:
            attck_id = deprecated_techniques[attck_id]
        if ot[attck_id] is not None:
            techniques.append(ot[attck_id](attck_id.lower()))
        elif attck_id not in missing_techniques:
            missing_techniques.add(attck_id)
            name = (technique['parent']['technique'] + ": " + technique['technique']
                    if technique['parent']
                    else technique['technique'])
            print(f"[*] Warning: A {technique['tactic']} technique {attck_id} ({name}) not found in the ontology.")
            print(f"    Go to {technique['attck_id_wiki']} to find out the replacement technique.")
            print(f"    Save the deprecated-replacement pair in the deprecated techniques CSV file.")

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

def resolve_sample_path(path):
    """Return path if report.json exists there, else try the SHA256-only variant (drop .JOB_ID)."""
    if os.path.exists(path + "/report.json"):
        return path
    parent, dirname = os.path.split(path.rstrip("/"))
    sha256_only = dirname.split(".")[0]
    fallback = os.path.join(parent, sha256_only)
    if os.path.exists(fallback + "/report.json"):
        print(f"[*] Resolved via SHA256-only fallback: {path} -> {fallback}")
        return fallback
    return path  # return original so the open() below gives the natural OSError

def map_to_ontology(malware_paths, benign_paths, ot, save_path, dataset_name):
    positive_examples = []
    negative_examples = []

    for path in malware_paths:
        path = resolve_sample_path(path)
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
        positive_examples.append(sample_hash)

    for path in benign_paths:
        path = resolve_sample_path(path)
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
        negative_examples.append(sample_hash)

    manifest = {
        "malware_paths": malware_paths,
        "benign_paths":  benign_paths
    }
    manifest_path = save_path + "/" + dataset_name + "_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    examples = {
        "positive_examples": positive_examples,
        "negative_examples": negative_examples
    }
    examples_path = save_path + "/" + dataset_name + "_examples.json"
    with open(examples_path, "w") as f:
        json.dump(examples, f, indent=2)

def map_ontology(ontology_path, ontology_name, namespace, malware_paths, benign_paths, save_path, dataset_name):
    owlready2.onto_path.append(ontology_path)
    ot = owlready2.get_ontology(ontology_name)
    ot.load()

    ns = ot.get_namespace(namespace)

    with ot:
        map_to_ontology(malware_paths, benign_paths, ns, save_path, dataset_name)
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

def create_ontology_dataset(path, name, namespace, malware_paths, benign_paths, dataset_name, save_path):
    map_ontology(path, name, namespace, malware_paths, benign_paths, save_path, dataset_name)
    clear_ontology(save_path, dataset_name + ".owl")

def get_all_subdirs(base_dir):
    seen_hashes = set()
    result = []
    for d in sorted(os.listdir(base_dir)):
        if not os.path.isdir(os.path.join(base_dir, d)):
            continue
        base_hash = d.split(".")[0]
        if base_hash in seen_hashes:
            continue
        seen_hashes.add(base_hash)
        result.append(os.path.join(base_dir, d))
    return result

def filter_valid_paths(paths, vx_families=None):
    valid = []
    for path in paths:
        report_path = path + "/report.json"
        try:
            with open(report_path) as f:
                sample = json.load(f)
            if 'md5' not in sample:
                print("[*] Pre-filter: no MD5, excluding: ", path)
                continue
            if vx_families is not None:
                family = sample.get('vx_family')
                if family not in vx_families:
                    continue
            valid.append(path)
        except Exception:
            print("[*] Pre-filter: could not read report, excluding: ", path)
    return valid

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert dynamic analysis reports to ontology dataset")
    
    parser.add_argument("--malware-dir",   default=None, help="Directory containing malware sample subdirectories")
    parser.add_argument("--benign-dir",    default=None, help="Directory containing benign sample subdirectories")
    parser.add_argument("--dataset-name",  required=True, help="Name for the output dataset")
    parser.add_argument("--num-malware",   type=int, default=None, help="Maximum number of malware samples to use (default: all)")
    parser.add_argument("--num-benign",    type=int, default=None, help="Maximum number of benign samples to use (default: all)")
    parser.add_argument("--ontology-path", default="./ontologies", help="Path to ontology directory (default: ./ontologies)")
    parser.add_argument("--ontology-name", default="maeco-lite-merged.owl", help="Ontology file name (default: maeco-lite-merged.owl)")
    parser.add_argument("--output-path",   default="./converted", help="Output directory (default: ./converted)")
    parser.add_argument("--variants",      type=int, default=1, help="Number of randomly sampled dataset variants to generate (default: 1)")
    parser.add_argument("--from-manifest", default=None, help="Path to a _manifest.json file to reproduce an exact previously generated dataset")
    parser.add_argument("--vx-family",     nargs="+",    default=None, metavar="FAMILY", help="Only include malware samples whose vx_family matches one of the given values")
    parser.add_argument("--namespace",     default="http://purl.org/orbis-security/maeco-lite#", help="Ontology namespace IRI (default: http://purl.org/orbis-security/maeco-lite#)")

    args = parser.parse_args()

    load_actions("actions.json")
    load_file_regex("file_regex.json")
    load_registry_regex("registry_regex.json")
    load_deprecated_techniques("deprecated-techniques.csv")

    if args.from_manifest:
        with open(args.from_manifest) as f:
            manifest = json.load(f)
        malware_paths = manifest["malware_paths"]
        benign_paths  = manifest["benign_paths"]
        print(f"[*] Reproducing from manifest: {args.from_manifest}")
        print(f"[*] Malware samples : {len(malware_paths)}")
        print(f"[*] Benign samples  : {len(benign_paths)}")
        create_ontology_dataset(args.ontology_path, args.ontology_name, args.namespace, malware_paths, benign_paths, args.dataset_name, args.output_path)
    else:
        if not args.malware_dir or not args.benign_dir:
            parser.error("--malware-dir and --benign-dir are required when not using --from-manifest")

        vx_families = set(args.vx_family) if args.vx_family else None
        all_malware_paths = filter_valid_paths(get_all_subdirs(args.malware_dir), vx_families=vx_families)
        all_benign_paths  = filter_valid_paths(get_all_subdirs(args.benign_dir))

        for variant in range(1, args.variants + 1):
            variant_name = args.dataset_name if args.variants == 1 else f"{args.dataset_name}_v{variant}"
            print(f"\n[*] Generating variant {variant}/{args.variants}: {variant_name}")

            malware_paths = random.sample(all_malware_paths, min(args.num_malware, len(all_malware_paths))) if args.num_malware is not None else random.sample(all_malware_paths, len(all_malware_paths))
            benign_paths  = random.sample(all_benign_paths,  min(args.num_benign,  len(all_benign_paths)))  if args.num_benign  is not None else random.sample(all_benign_paths,  len(all_benign_paths))

            print(f"[*] Malware samples : {len(malware_paths)}")
            print(f"[*] Benign samples  : {len(benign_paths)}")

            create_ontology_dataset(args.ontology_path, args.ontology_name, args.namespace, malware_paths, benign_paths, variant_name, args.output_path)
