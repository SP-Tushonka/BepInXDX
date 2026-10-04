using System;
using System.IO;
using System.Runtime.InteropServices;
using MonoMod.Utils;

namespace BepInEx.Unix;

internal static class UnixStreamHelper
{
    public delegate int dupDelegate(int fd);

    public delegate int fcloseDelegate(IntPtr stream);

    public delegate IntPtr fdopenDelegate(int fd, string mode);

    public delegate int fflushDelegate(IntPtr stream);

    public delegate IntPtr freadDelegate(IntPtr ptr, IntPtr size, IntPtr nmemb, IntPtr stream);

    public delegate int fwriteDelegate(IntPtr ptr, IntPtr size, IntPtr nmemb, IntPtr stream);

    public delegate int isattyDelegate(int fd);

    public static dupDelegate dup;

    public static fdopenDelegate fdopen;

    public static freadDelegate fread;

    public static fwriteDelegate fwrite;

    public static fcloseDelegate fclose;

    public static fflushDelegate fflush;

    public static isattyDelegate isatty;

    static UnixStreamHelper()
    {
        var libc = OpenLibc();
        dup = GetExport<dupDelegate>(libc, "dup");
        fdopen = GetExport<fdopenDelegate>(libc, "fdopen");
        fread = GetExport<freadDelegate>(libc, "fread");
        fwrite = GetExport<fwriteDelegate>(libc, "fwrite");
        fclose = GetExport<fcloseDelegate>(libc, "fclose");
        fflush = GetExport<fflushDelegate>(libc, "fflush");
        isatty = GetExport<isattyDelegate>(libc, "isatty");
    }

    private static IntPtr OpenLibc()
    {
        string[] names =
        {
            "libc.so.6",               // Ubuntu glibc
            "libc",                    // Linux glibc
            "/usr/lib/libSystem.dylib" // OSX POSIX
        };

        foreach (var name in names)
            if (DynDll.TryOpenLibrary(name, out var handle))
                return handle;

        throw new DllNotFoundException("libc");
    }

    private static T GetExport<T>(IntPtr library, string name) where T : Delegate =>
        (T) Marshal.GetDelegateForFunctionPointer(library.GetExport(name), typeof(T));

    public static Stream CreateDuplicateStream(int fileDescriptor)
    {
        var newFd = dup(fileDescriptor);

        return new UnixStream(newFd, FileAccess.Write);
    }
}
