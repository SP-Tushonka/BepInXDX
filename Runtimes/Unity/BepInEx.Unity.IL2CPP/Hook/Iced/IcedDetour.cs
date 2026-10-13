extern alias IcedLib;
using System;
using System.Runtime.InteropServices;
using IcedLib::Iced.Intel;

namespace BepInEx.Unity.IL2CPP.Hook.Iced;

/// <summary>
///     x64 Windows detour that patches a function with a jump to a relay near it, or with an absolute jump when no memory
///     near it is free. The overwritten instructions are relocated with Iced
/// </summary>
internal sealed unsafe class IcedDetour : BaseNativeDetour<IcedDetour>
{
    private const int NearPatchSize = 5;
    private const int FarPatchSize = 14;
    private const int PaddingPatchSize = 6;
    private const int RelaySize = 16;
    private const int MaxTrampolineSize = 256;
    private const uint PageExecuteReadWrite = 0x40;

    private static bool surroundingsLogged;

    private byte[] patch;
    private byte[] originalBytes;

    public IcedDetour(nint originalMethodPtr, Delegate detourMethod) : base(originalMethodPtr, detourMethod) { }

    protected override void PrepareImpl()
    {
        if (TryPrepareNear(out var error))
            return;

        if (error != null)
            throw new InvalidOperationException($"Cannot hook 0x{OriginalMethodPtr:X}, {error}");

        LogSurroundingsOnce();
        if (!TryPrepareFar(out error))
            throw new InvalidOperationException($"Cannot hook 0x{OriginalMethodPtr:X}, {error}");
    }

    protected override void ApplyImpl()
    {
        originalBytes = new byte[patch.Length];
        Marshal.Copy(OriginalMethodPtr, originalBytes, 0, originalBytes.Length);
        WriteCode(OriginalMethodPtr, patch);
    }

    protected override void UndoImpl() => WriteCode(OriginalMethodPtr, originalBytes);

    protected override void FreeImpl() { }

    /// <summary>
    ///     Patch with a five byte jump to a relay next to the function, the relay jumps on to the detour
    /// </summary>
    /// <param name="error">Why the function cannot be hooked at all, null when only near memory was missing</param>
    /// <returns>True when prepared</returns>
    private bool TryPrepareNear(out string error)
    {
        var instructions = X64Relocator.Read(OriginalMethodPtr, NearPatchSize, out error);
        if (instructions == null)
            return false;

        string relocationError = null;
        var relay = X64CodeMemory.Write(OriginalMethodPtr, RelaySize + MaxTrampolineSize, address =>
        {
            WriteAbsoluteJump(address, DetourMethodPtr);
            var length = X64Relocator.Write(instructions, address + RelaySize, MaxTrampolineSize, false, out relocationError);
            return length < 0 ? -1 : RelaySize + length;
        });

        error = relocationError;
        if (relay == 0)
            return false;

        TrampolinePtr = relay + RelaySize;
        patch = new byte[NearPatchSize];
        patch[0] = 0xE9;
        BitConverter.TryWriteBytes(patch.AsSpan(1), (int) (relay - (OriginalMethodPtr + NearPatchSize)));
        return true;
    }

    /// <summary>
    ///     Patch with a fourteen byte absolute jump, the trampoline may then live anywhere. A function too short for it
    ///     gets a six byte jmp [rip+disp32] whose target sits in nearby int3 padding
    /// </summary>
    /// <param name="error">Why the function cannot be hooked</param>
    /// <returns>True when prepared</returns>
    private bool TryPrepareFar(out string error)
    {
        var instructions = X64Relocator.Read(OriginalMethodPtr, FarPatchSize, out error);
        if (instructions != null)
        {
            patch = new byte[FarPatchSize];
            fixed (byte* bytes = patch)
                WriteAbsoluteJump((nint) bytes, DetourMethodPtr);

            return TryWriteFarTrampoline(instructions, out error);
        }

        instructions = X64Relocator.Read(OriginalMethodPtr, PaddingPatchSize, out var shortError);
        if (instructions == null)
        {
            error = shortError;
            return false;
        }

        var slot = X64CodeMemory.ClaimPadding(OriginalMethodPtr);
        if (slot == 0)
        {
            error = $"{error} and no int3 padding near it can hold a jump target";
            return false;
        }

        var target = BitConverter.GetBytes((long) DetourMethodPtr);
        WriteCode(slot, target);
        patch = new byte[PaddingPatchSize];
        patch[0] = 0xFF;
        patch[1] = 0x25;
        BitConverter.TryWriteBytes(patch.AsSpan(2), (int) (slot - (OriginalMethodPtr + PaddingPatchSize)));
        return TryWriteFarTrampoline(instructions, out error);
    }

    private bool TryWriteFarTrampoline(InstructionList instructions, out string error)
    {
        string relocationError = null;
        TrampolinePtr = X64CodeMemory.Write(0, MaxTrampolineSize,
                                            address => X64Relocator.Write(instructions, address, MaxTrampolineSize, true,
                                                                          out relocationError));
        error = TrampolinePtr == 0 ? relocationError ?? "no executable memory could be allocated" : null;
        return TrampolinePtr != 0;
    }

    private void LogSurroundingsOnce()
    {
        if (surroundingsLogged)
            return;

        surroundingsLogged = true;
        Logger.LogWarning($"No free memory near 0x{OriginalMethodPtr:X}, hooks there use absolute jumps. Address space around it: "
                        + X64CodeMemory.DescribeSurroundings(OriginalMethodPtr));
    }

    /// <summary>
    ///     Write jmp qword ptr [rip+0] followed by the target address
    /// </summary>
    private static void WriteAbsoluteJump(nint at, nint target)
    {
        var bytes = (byte*) at;
        bytes[0] = 0xFF;
        bytes[1] = 0x25;
        *(int*) (bytes + 2) = 0;
        *(long*) (bytes + 6) = target;
    }

    private static void WriteCode(nint address, byte[] bytes)
    {
        VirtualProtect(address, (nuint) bytes.Length, PageExecuteReadWrite, out var oldProtect);
        Marshal.Copy(bytes, 0, address, bytes.Length);
        VirtualProtect(address, (nuint) bytes.Length, oldProtect, out _);
        FlushInstructionCache(GetCurrentProcess(), address, (nuint) bytes.Length);
    }

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(nint address, nuint size, uint newProtect, out uint oldProtect);

    [DllImport("kernel32.dll")]
    private static extern bool FlushInstructionCache(nint process, nint address, nuint size);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();
}
