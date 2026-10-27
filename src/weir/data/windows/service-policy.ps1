# Shared native SCM configuration/readback. Configure is used only by the installer.
if (-not ('WeirAdmission.ServicePolicy' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace WeirAdmission {
  public sealed class Policy {
    public int SidType;
    public string[] RequiredPrivileges;
    public int ResetSeconds;
    public int[] Actions;
    public int[] Delays;
    public bool NonCrashFailures;
    public string SecurityDescriptor;
  }
  public static class ServicePolicy {
    [StructLayout(LayoutKind.Sequential)] struct Action { public int Type; public int Delay; }
    [StructLayout(LayoutKind.Sequential)] struct Failures {
      public int Reset; public IntPtr Reboot; public IntPtr Command; public int Count; public IntPtr Actions;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenSCManager(string machine, string database, int access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenService(IntPtr manager, string name, int access);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryServiceConfig2(IntPtr service, int level, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ChangeServiceConfig2(IntPtr service, int level, IntPtr buffer);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool QueryServiceObjectSecurity(IntPtr service, int flags, byte[] buffer, int size, out int needed);
    static void Check(bool result) { if (!result) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static IntPtr Open(string name, bool write) {
      if (name != "WeirAdmission") throw new ArgumentException("Unexpected service target");
      IntPtr manager = OpenSCManager(null, null, 1);
      if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
      try {
        // Configuring SC_ACTION_RESTART also requires SERVICE_START.
        IntPtr service = OpenService(manager, name, 0x20001 | (write ? 0x12 : 0));
        if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        return service;
      } finally { CloseServiceHandle(manager); }
    }
    static IntPtr Query(IntPtr service, int level) {
      int needed;
      QueryServiceConfig2(service, level, IntPtr.Zero, 0, out needed);
      if (needed < 4 || needed > 65536) throw new InvalidOperationException("Invalid SCM result size");
      IntPtr buffer = Marshal.AllocHGlobal(needed);
      try { Check(QueryServiceConfig2(service, level, buffer, needed, out needed)); return buffer; }
      catch { Marshal.FreeHGlobal(buffer); throw; }
    }
    public static Policy Read(string name) {
      IntPtr service = Open(name, false);
      try {
        Policy result = new Policy();
        IntPtr buffer = Query(service, 5);
        try { result.SidType = Marshal.ReadInt32(buffer); } finally { Marshal.FreeHGlobal(buffer); }
        buffer = Query(service, 6);
        try {
          IntPtr cursor = Marshal.ReadIntPtr(buffer);
          var privileges = new List<string>();
          for (int n=0; cursor != IntPtr.Zero && n<64; n++) {
            string value = Marshal.PtrToStringUni(cursor);
            if (String.IsNullOrEmpty(value)) break;
            privileges.Add(value); cursor = IntPtr.Add(cursor, (value.Length + 1) * 2);
          }
          result.RequiredPrivileges = privileges.ToArray();
        } finally { Marshal.FreeHGlobal(buffer); }
        buffer = Query(service, 2);
        try {
          Failures failure = (Failures)Marshal.PtrToStructure(buffer, typeof(Failures));
          if (failure.Count < 0 || failure.Count > 16 || !String.IsNullOrEmpty(Marshal.PtrToStringUni(failure.Command)) || !String.IsNullOrEmpty(Marshal.PtrToStringUni(failure.Reboot))) throw new InvalidOperationException("Unexpected service recovery policy");
          result.ResetSeconds = failure.Reset;
          result.Actions = new int[failure.Count]; result.Delays = new int[failure.Count];
          for (int n=0; n<failure.Count; n++) {
            Action action = (Action)Marshal.PtrToStructure(IntPtr.Add(failure.Actions, n * Marshal.SizeOf(typeof(Action))), typeof(Action));
            result.Actions[n] = action.Type; result.Delays[n] = action.Delay;
          }
        } finally { Marshal.FreeHGlobal(buffer); }
        buffer = Query(service, 4);
        try { result.NonCrashFailures = Marshal.ReadInt32(buffer) != 0; } finally { Marshal.FreeHGlobal(buffer); }
        int bytes;
        QueryServiceObjectSecurity(service, 5, null, 0, out bytes);
        if (bytes < 1 || bytes > 65536) throw new InvalidOperationException("Invalid service DACL size");
        byte[] security = new byte[bytes];
        Check(QueryServiceObjectSecurity(service, 5, security, security.Length, out bytes));
        result.SecurityDescriptor = new RawSecurityDescriptor(security, 0).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
        return result;
      } finally { CloseServiceHandle(service); }
    }
    public static void Configure(string name) {
      IntPtr service = Open(name, true);
      IntPtr value = Marshal.AllocHGlobal(Math.Max(8, Marshal.SizeOf(typeof(Failures))));
      IntPtr privileges = Marshal.StringToHGlobalUni("SeChangeNotifyPrivilege\0");
      IntPtr actions = Marshal.AllocHGlobal(3 * Marshal.SizeOf(typeof(Action)));
      try {
        Marshal.WriteInt32(value, 1); Check(ChangeServiceConfig2(service, 5, value));
        Check(ChangeServiceConfig2(service, 4, value));
        Marshal.WriteIntPtr(value, privileges); Check(ChangeServiceConfig2(service, 6, value));
        Action[] sequence = { new Action { Type=1, Delay=5000 }, new Action { Type=1, Delay=30000 }, new Action { Type=0, Delay=0 } };
        for (int n=0; n<3; n++) Marshal.StructureToPtr(sequence[n], IntPtr.Add(actions, n * Marshal.SizeOf(typeof(Action))), false);
        Failures failure = new Failures { Reset=86400, Reboot=IntPtr.Zero, Command=IntPtr.Zero, Count=3, Actions=actions };
        Marshal.StructureToPtr(failure, value, false); Check(ChangeServiceConfig2(service, 2, value));
      } finally { Marshal.FreeHGlobal(value); Marshal.FreeHGlobal(privileges); Marshal.FreeHGlobal(actions); CloseServiceHandle(service); }
    }
  }
}
'@
}
