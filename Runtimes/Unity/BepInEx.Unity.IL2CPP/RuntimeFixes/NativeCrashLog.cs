using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using BepInEx.Logging;

namespace BepInEx.IL2CPP.RuntimeFixes;

/// <summary>
///     Writes a native crash to the log before Windows ends the process.
///     A fault in il2cpp or engine code otherwise only reaches the Windows event log
/// </summary>
internal static unsafe class NativeCrashLog
{
    private const uint ExceptionAccessViolation = 0xC0000005;
    private const uint ManagedException = 0xE0434352;
    private const uint GetModuleHandleFromAddress = 0x4;
    private const uint GetModuleHandleUnchangedRefcount = 0x2;
    private const int ExceptionContinueSearch = 0;

    private static nint previousFilter;

    /// <summary>
    ///     Log faults the runtime turns into unhandled exceptions and install the unhandled exception filter for the
    ///     rest, chaining to the one already in place
    /// </summary>
    public static void Apply()
    {
        // An access violation under managed frames ends the process through the runtime, never reaching the filter
        AppDomain.CurrentDomain.UnhandledException += (_, args) => Write($"Unhandled exception, the process is ending{Environment.NewLine}{args.ExceptionObject}");

        if (!OperatingSystem.IsWindows())
            return;

        previousFilter = SetUnhandledExceptionFilter((nint) (delegate* unmanaged<ExceptionPointers*, int>) &OnUnhandledException);
    }

    private static void Write(string message)
    {
        try
        {
            Logger.Log(LogLevel.Fatal, message);
            foreach (var listener in Logger.Listeners.OfType<DiskLogListener>())
                listener.LogWriter?.Flush();
        }
        catch
        {
            // The process is ending either way
        }
    }

    [UnmanagedCallersOnly]
    private static int OnUnhandledException(ExceptionPointers* pointers)
    {
        try
        {
            var record = pointers->ExceptionRecord;

            // A managed exception was already logged by the UnhandledException handler
            if (record->ExceptionCode == ManagedException)
                return ChainToPrevious(pointers);

            var message = new StringBuilder();
            message.Append($"Native crash 0x{record->ExceptionCode:X8} at {Describe(record->ExceptionAddress)}");
            if (record->ExceptionCode == ExceptionAccessViolation && record->NumberParameters >= 2)
                message.Append($", {(record->ExceptionInformation[0] == 0 ? "reading" : "writing")} 0x{record->ExceptionInformation[1]:X}");

            message.AppendLine().Append(new StackTrace(1, false));
            Write(message.ToString());
        }
        catch
        {
            // The process is ending, the previous filter still has to run
        }

        return ChainToPrevious(pointers);
    }

    private static int ChainToPrevious(ExceptionPointers* pointers) =>
        previousFilter != 0
            ? ((delegate* unmanaged<ExceptionPointers*, int>) previousFilter)(pointers)
            : ExceptionContinueSearch;

    /// <summary>
    ///     Format an address as module plus offset
    /// </summary>
    /// <param name="address">Code address</param>
    /// <returns>Module name and offset, or the raw address outside any module</returns>
    private static string Describe(nint address)
    {
        if (!GetModuleHandleExW(GetModuleHandleFromAddress | GetModuleHandleUnchangedRefcount, address, out var module))
            return $"0x{address:X}";

        var name = new char[260];
        fixed (char* buffer = name)
        {
            var length = GetModuleFileNameW(module, buffer, (uint) name.Length);
            return $"{Path.GetFileName(new string(buffer, 0, (int) length))}+0x{address - module:X}";
        }
    }

    [DllImport("kernel32.dll")]
    private static extern nint SetUnhandledExceptionFilter(nint filter);

    [DllImport("kernel32.dll")]
    private static extern bool GetModuleHandleExW(uint flags, nint address, out nint module);

    [DllImport("kernel32.dll")]
    private static extern uint GetModuleFileNameW(nint module, char* fileName, uint size);

    [StructLayout(LayoutKind.Sequential)]
    private struct ExceptionPointers
    {
        public ExceptionRecord* ExceptionRecord;
        public nint ContextRecord;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExceptionRecord
    {
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public ExceptionRecord* InnerRecord;
        public nint ExceptionAddress;
        public uint NumberParameters;
        public fixed ulong ExceptionInformation[15];
    }
}
