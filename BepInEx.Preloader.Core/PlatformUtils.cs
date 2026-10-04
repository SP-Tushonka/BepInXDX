using System;
using System.Runtime.InteropServices;
using MonoMod.Utils;

namespace BepInEx.Preloader.Core;

internal static class PlatformUtils
{
    public static readonly bool ProcessIs64Bit = IntPtr.Size >= 8;
    public static Version WindowsVersion { get; set; }
    public static string WineVersion { get; set; }

    public static string LinuxArchitecture { get; set; }
    public static string LinuxKernelVersion { get; set; }

    public static bool Is64BitOperatingSystem { get; private set; }

    public static bool IsWine => WineVersion != null;

    [DllImport("libc.so.6", EntryPoint = "uname", CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi)]
    private static extern IntPtr uname_linux(ref utsname_linux utsname);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern bool RtlGetVersion(ref WindowsOSVersionInfoExW versionInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LoadLibrary(string libraryName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    /// <summary>
    ///     Collects the OS version details that MonoMod's PlatformDetection does not expose.
    /// </summary>
    public static void SetPlatform()
    {
        var os = PlatformDetection.OS;

        if (os.Is(OSKind.Windows))
        {
            var windowsVersionInfo = new WindowsOSVersionInfoExW();
            RtlGetVersion(ref windowsVersionInfo);

            WindowsVersion = new Version((int) windowsVersionInfo.dwMajorVersion,
                                         (int) windowsVersionInfo.dwMinorVersion,
                                         (int) windowsVersionInfo.dwBuildNumber);

            var ntDll = LoadLibrary("ntdll.dll");
            if (ntDll != IntPtr.Zero)
            {
                var wineGetVersion = GetProcAddress(ntDll, "wine_get_version");
                if (wineGetVersion != IntPtr.Zero)
                {
                    var getVersion = Marshal.GetDelegateForFunctionPointer(wineGetVersion, typeof(GetWineVersionDelegate)) as GetWineVersionDelegate;
                    WineVersion = getVersion();
                }
            }
        }

        // Is64BitOperatingSystem has been added in .NET Framework 4.0
        var m_get_Is64BitOperatingSystem =
            typeof(Environment).GetProperty("Is64BitOperatingSystem")?.GetGetMethod();
        Is64BitOperatingSystem = m_get_Is64BitOperatingSystem != null
                                     ? (bool) m_get_Is64BitOperatingSystem.Invoke(null, new object[0])
                                     : IntPtr.Size >= 8;

        if (os.Is(OSKind.Linux) && Type.GetType("Mono.Runtime") != null)
        {
            var utsname_linux = new utsname_linux();
            uname_linux(ref utsname_linux);

            LinuxArchitecture = utsname_linux.machine;
            LinuxKernelVersion = utsname_linux.version;
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.LPStr)]
    private delegate string GetWineVersionDelegate();

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct WindowsOSVersionInfoExW
    {
        public uint dwOSVersionInfoSize;
        public uint dwMajorVersion;
        public uint dwMinorVersion;
        public uint dwBuildNumber;
        public uint dwPlatformId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;

        public ushort wServicePackMajor;
        public ushort wServicePackMinor;
        public ushort wSuiteMask;
        public byte wProductType;
        public byte wReserved;

        public WindowsOSVersionInfoExW()
        {
            dwOSVersionInfoSize = (uint) Marshal.SizeOf(typeof(WindowsOSVersionInfoExW));
            dwMajorVersion = 0;
            dwMinorVersion = 0;
            dwBuildNumber = 0;
            dwPlatformId = 0;
            szCSDVersion = null;
            wServicePackMajor = 0;
            wServicePackMinor = 0;
            wSuiteMask = 0;
            wProductType = 0;
            wReserved = 0;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct utsname_linux
    {
        private const int linux_utslen = 65;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = linux_utslen)]
        public string sysname;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = linux_utslen)]
        public string nodename;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = linux_utslen)]
        public string release;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = linux_utslen)]
        public string version;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = linux_utslen)]
        public string machine;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = linux_utslen)]
        public string domainname;
    }
}
