using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace BepInEx.Unity.IL2CPP.Hook;

/// <summary>
///     Executable memory for x64 trampolines and relays, carved out of 64 KB chunks
/// </summary>
internal static unsafe class X64CodeMemory
{
    /// <summary>
    ///     How far a chunk may sit from the code it serves. A rel32 reaches 2 GB, this leaves room for the size of a function
    /// </summary>
    public const long NearRange = 0x70000000;

    private const int ChunkSize = 0x10000;
    private const uint MemCommitReserve = 0x3000;
    private const uint MemFree = 0x10000;
    private const uint MemImage = 0x1000000;
    private const uint PageExecuteReadWrite = 0x40;

    private const long PaddingSearchRange = 0x100000;

    private static readonly object ChunkLock = new();
    private static readonly List<Chunk> Chunks = [];
    private static readonly HashSet<long> ClaimedPadding = [];

    /// <summary>
    ///     Write code into free space of a chunk
    /// </summary>
    /// <param name="near">Address the space must stay within rel32 reach of, 0 for anywhere</param>
    /// <param name="capacity">Most bytes the writer may use</param>
    /// <param name="write">Writes at the given address and returns the bytes used, or -1 when it wrote nothing</param>
    /// <returns>Address written to, 0 when no chunk could be found or nothing was written</returns>
    public static nint Write(nint near, int capacity, Func<nint, int> write)
    {
        lock (ChunkLock)
        {
            var chunk = FindChunk(near, capacity);
            if (chunk == null)
                return 0;

            var address = chunk.Start + chunk.Used;
            var used = write(address);
            if (used < 0)
                return 0;

            // Keep code 16 byte aligned like compiled functions
            chunk.Used += (used + 15) & ~15;
            return address;
        }
    }

    /// <summary>
    ///     Claim eight bytes of the int3 padding compilers place before a 16 byte aligned function, nearest to an address.
    ///     Padding is never executed, so it can hold the target of a jump when no memory near the code is free
    /// </summary>
    /// <param name="near">Code the padding must be reachable from</param>
    /// <returns>Start of the claimed bytes, 0 when none were found</returns>
    public static nint ClaimPadding(nint near)
    {
        if (VirtualQuery(near, out var info, (nuint) sizeof(MemoryBasicInformation)) == 0)
            return 0;

        var regionStart = (long) info.BaseAddress;
        var regionEnd = regionStart + (long) info.RegionSize;
        lock (ChunkLock)
        {
            var origin = (long) near & ~15L;
            for (long distance = 0; distance < PaddingSearchRange; distance += 16)
            {
                foreach (var functionStart in new[] { origin + distance, origin - distance })
                {
                    var slot = functionStart - 8;
                    if (slot < regionStart || functionStart >= regionEnd || ClaimedPadding.Contains(slot))
                        continue;

                    if (*(ulong*) slot == 0xCCCCCCCCCCCCCCCC && *(byte*) functionStart != 0xCC)
                    {
                        ClaimedPadding.Add(slot);
                        return (nint) slot;
                    }
                }
            }
        }

        return 0;
    }

    /// <summary>
    ///     Describe what occupies the address space around an address, for logs about missing near memory
    /// </summary>
    /// <param name="near">Address to describe the surroundings of</param>
    /// <returns>Free space and the largest allocations within rel32 reach</returns>
    public static string DescribeSurroundings(nint near)
    {
        var start = Math.Max((long) near - int.MaxValue, ChunkSize);
        var end = (long) near + int.MaxValue;
        long free = 0, largestFree = 0;
        var allocations = new Dictionary<long, (long Size, uint Type)>();
        for (var address = start; address < end;)
        {
            if (VirtualQuery((nint) address, out var info, (nuint) sizeof(MemoryBasicInformation)) == 0)
                break;

            var size = Math.Min((long) info.BaseAddress + (long) info.RegionSize, end) - Math.Max((long) info.BaseAddress, start);
            if (info.State == MemFree)
            {
                free += size;
                largestFree = Math.Max(largestFree, size);
            }
            else
            {
                var owner = (long) info.AllocationBase;
                allocations[owner] = (allocations.GetValueOrDefault(owner).Size + size, info.Type);
            }

            address = (long) info.BaseAddress + (long) info.RegionSize;
        }

        var text = new StringBuilder($"free {free / 0x100000} MB, largest free block {largestFree / 0x10000 * 64} KB, largest allocations:");
        foreach (var (owner, (size, type)) in allocations.OrderByDescending(pair => pair.Value.Size).Take(6))
            text.Append($" 0x{owner:X} {size / 0x100000} MB {(type == MemImage ? ModuleName(owner) : "private or mapped")};");

        return text.ToString();
    }

    private static Chunk FindChunk(nint near, int capacity)
    {
        foreach (var chunk in Chunks)
        {
            if (chunk.Used + capacity <= ChunkSize && (near == 0 || Math.Abs((long) chunk.Start - near) < NearRange))
                return chunk;
        }

        var start = near == 0 ? VirtualAlloc(0, ChunkSize, MemCommitReserve, PageExecuteReadWrite) : AllocateNear(near);
        if (start == 0)
            return null;

        var allocated = new Chunk(start);
        Chunks.Add(allocated);
        return allocated;
    }

    /// <summary>
    ///     Allocate a chunk in the first free region within reach of an address
    /// </summary>
    /// <param name="near">Address the chunk must reach</param>
    /// <returns>Start of the chunk, 0 when no region is free</returns>
    private static nint AllocateNear(nint near)
    {
        var address = (Math.Max((long) near - NearRange, ChunkSize) + ChunkSize - 1) & ~(ChunkSize - 1L);
        var end = (long) near + NearRange;
        while (address < end)
        {
            if (VirtualQuery((nint) address, out var info, (nuint) sizeof(MemoryBasicInformation)) == 0)
                return 0;

            if (info.State == MemFree && (long) info.RegionSize >= ChunkSize)
            {
                var allocated = VirtualAlloc((nint) address, ChunkSize, MemCommitReserve, PageExecuteReadWrite);
                if (allocated != 0)
                    return allocated;
            }

            address = ((long) info.BaseAddress + (long) info.RegionSize + ChunkSize - 1) & ~(ChunkSize - 1L);
        }

        return 0;
    }

    private static string ModuleName(long module)
    {
        var buffer = new char[260];
        var length = GetModuleFileNameW((nint) module, buffer, buffer.Length);
        return length == 0 ? "image" : System.IO.Path.GetFileName(new string(buffer, 0, (int) length));
    }

    [DllImport("kernel32.dll")]
    private static extern nint VirtualAlloc(nint address, nuint size, uint allocationType, uint protect);

    [DllImport("kernel32.dll")]
    private static extern nuint VirtualQuery(nint address, out MemoryBasicInformation buffer, nuint length);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameW(nint module, [Out] char[] fileName, int size);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private sealed class Chunk(nint start)
    {
        public nint Start { get; } = start;
        public int Used { get; set; }
    }
}
