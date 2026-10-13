using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace BepInEx.Unity.IL2CPP.Hook.Dobby;

/// <summary>
///     Predicts whether Dobby finds memory near a function for the address its jump reads. When it finds none it writes
///     through a null pointer and the process dies, so hooks it would fail on have to go elsewhere before Dobby sees them
/// </summary>
internal static unsafe class DobbyNearSearch
{
    // Dobby searches 2 GB either side in steps of the allocation granularity, see NearMemoryArena.cc in BepInEx/Dobby 1.0.5
    private const ulong Range = 2UL * 1024 * 1024 * 1024;
    private const ulong Page = 0x10000;
    private const uint MemCommit = 0x1000;
    private const uint MemReserve = 0x2000;
    private const uint MemFree = 0x10000;

    /// <summary>
    ///     Replay search_near_blank_page without allocating
    /// </summary>
    /// <param name="function">Function about to be hooked</param>
    /// <returns>True when Dobby's search would find a page</returns>
    public static bool FindsPage(nint function)
    {
        var position = (ulong) function;
        var min = NextPage(position > position - Range ? position - Range : 0);
        var max = PrevPage(position < position + Range ? position + Range : ulong.MaxValue);
        var layout = Layout();
        if (layout.Count == 0)
            return true;

        var assume = min;
        if (min < layout[0].Start && IsFree(assume))
            return true;

        if (max < layout[layout.Count - 1].End && IsFree(assume))
            return true;

        for (var i = 0; i < layout.Count; i++)
        {
            var region = layout[i];
            if (region.End >= max || region.Start < min)
                continue;

            if (i >= 1 && assume == min)
            {
                var previousEnd = NextPage(layout[i - 1].End);
                if (region.Start > previousEnd)
                {
                    assume = Math.Max(min, previousEnd);
                    if (IsFree(assume))
                        return true;
                }
            }

            if (i <= layout.Count - 2 && region.End < layout[i + 1].Start)
            {
                assume = NextPage(region.End);
                if (IsFree(assume))
                    return true;
            }
        }

        return false;
    }

    private static ulong NextPage(ulong address) => (address & ~(Page - 1)) + Page;

    private static ulong PrevPage(ulong address) => (address & ~(Page - 1)) - Page;

    /// <summary>
    ///     Whether VirtualAlloc of one allocation granule at the address would succeed
    /// </summary>
    private static bool IsFree(ulong address) =>
        VirtualQuery((nint) address, out var info, (nuint) sizeof(MemoryBasicInformation)) != 0
     && info.State == MemFree
     && (ulong) info.BaseAddress + info.RegionSize >= address + Page;

    /// <summary>
    ///     Committed and reserved regions in address order, the way Dobby lists them
    /// </summary>
    private static List<(ulong Start, ulong End)> Layout()
    {
        var layout = new List<(ulong Start, ulong End)>();
        ulong address = 0;
        while (VirtualQuery((nint) address, out var info, (nuint) sizeof(MemoryBasicInformation)) != 0)
        {
            var start = (ulong) info.BaseAddress;
            if ((info.State & (MemCommit | MemReserve)) != 0)
                layout.Add((start, start + info.RegionSize));

            address = start + info.RegionSize;
        }

        return layout;
    }

    [DllImport("kernel32.dll")]
    private static extern nuint VirtualQuery(nint address, out MemoryBasicInformation buffer, nuint length);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
