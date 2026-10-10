extern alias IcedLib;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using BepInEx.Logging;
using IcedLib::Iced.Intel;

namespace BepInEx.Unity.IL2CPP.Hook.Dobby;

/// <summary>
///     Builds the x64 trampoline for a Dobby hook with Iced.
///     Dobby's own relocation corrupts short branches and imm64 moves in the bytes it overwrites
/// </summary>
internal static unsafe class DobbyTrampoline
{
    // Dobby overwrites a hooked function with a six byte jmp [rip+disp32]
    private const int PatchSize = 6;
    private const int MaxTrampolineSize = 128;
    private const int ChunkSize = 0x10000;
    private const long NearRange = 0x70000000;
    private const uint MemCommitReserve = 0x3000;
    private const uint MemFree = 0x10000;
    private const uint PageExecuteReadWrite = 0x40;

    private static readonly object ChunkLock = new();
    private static readonly List<Chunk> Chunks = [];

    /// <summary>
    ///     Relocate the instructions Dobby overwrites into new memory near the original, followed by a jump back
    /// </summary>
    /// <param name="original">Function being hooked, still unmodified</param>
    /// <param name="logger">Log for functions that cannot be relocated</param>
    /// <returns>Trampoline that runs the original function, 0 when Dobby's own has to be used</returns>
    public static nint Build(nint original, ManualLogSource logger)
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64 || !OperatingSystem.IsWindows())
            return 0;

        var decoder = Decoder.Create(64, new PointerCodeReader(original), (ulong) original);
        var instructions = new InstructionList();
        while (decoder.IP < (ulong) original + PatchSize)
        {
            var instruction = decoder.Decode();
            if (instruction.IsInvalid)
            {
                logger.LogWarning($"Hook at 0x{original:X} starts with code that cannot be decoded, calling the original may crash");
                return 0;
            }

            instructions.Add(instruction);
        }

        instructions.Add(Instruction.CreateBranch(Code.Jmp_rel32_64, decoder.IP));

        lock (ChunkLock)
        {
            var chunk = FindChunk(original);
            if (chunk == null)
            {
                logger.LogWarning($"Hook at 0x{original:X} has no free memory near it to relocate into, calling the original may crash");
                return 0;
            }

            var memory = chunk.Start + chunk.Used;
            var writer = new BufferCodeWriter(memory, MaxTrampolineSize);
            if (!BlockEncoder.TryEncode(64, new InstructionBlock(writer, instructions, (ulong) memory), out var error, out _))
            {
                logger.LogWarning($"Hook at 0x{original:X} could not be relocated ({error}), calling the original may crash");
                return 0;
            }

            // Keep trampolines 16 byte aligned like compiled functions
            chunk.Used += (writer.Length + 15) & ~15;
            return memory;
        }
    }

    /// <summary>
    ///     Get a chunk within rel32 reach of a function that has room for another trampoline
    /// </summary>
    /// <param name="near">Function the trampoline jumps back into</param>
    /// <returns>Chunk to write into, null when nothing near is free</returns>
    private static Chunk FindChunk(nint near)
    {
        foreach (var chunk in Chunks)
        {
            if (chunk.Used + MaxTrampolineSize <= ChunkSize && Math.Abs((long) chunk.Start - near) < NearRange)
                return chunk;
        }

        var start = AllocateNear(near);
        if (start == 0)
            return null;

        var allocated = new Chunk(start);
        Chunks.Add(allocated);
        return allocated;
    }

    /// <summary>
    ///     Find a free region within rel32 reach of an address and allocate a chunk there
    /// </summary>
    /// <param name="near">Address the chunk must reach</param>
    /// <returns>Start of the chunk, 0 when no region is free</returns>
    private static nint AllocateNear(nint near)
    {
        var address = Math.Max((long) near - NearRange, ChunkSize) & ~(ChunkSize - 1L);
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

    [DllImport("kernel32.dll")]
    private static extern nint VirtualAlloc(nint address, nuint size, uint allocationType, uint protect);

    [DllImport("kernel32.dll")]
    private static extern nuint VirtualQuery(nint address, out MemoryBasicInformation buffer, nuint length);

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

    private sealed class PointerCodeReader(nint start) : CodeReader
    {
        private int offset;

        public override int ReadByte() => ((byte*) start)[offset++];
    }

    private sealed class BufferCodeWriter(nint start, int capacity) : CodeWriter
    {
        public int Length { get; private set; }

        public override void WriteByte(byte value)
        {
            if (Length >= capacity)
                throw new InvalidOperationException("Trampoline is larger than its reserved space");

            ((byte*) start)[Length++] = value;
        }
    }
}
