using System;
using System.Runtime.InteropServices;
using BepInEx.Logging;

namespace BepInEx.Unity.IL2CPP.Hook.Dobby;

/// <summary>
///     Builds the x64 trampoline for a Dobby hook with Iced.
///     Dobby's own relocation corrupts short branches and imm64 moves in the bytes it overwrites
/// </summary>
internal static class DobbyTrampoline
{
    // Dobby overwrites a hooked function with a six byte jmp [rip+disp32]
    private const int PatchSize = 6;
    private const int MaxTrampolineSize = 128;

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

        var instructions = X64Relocator.Read(original, PatchSize, out var error);
        if (instructions != null)
        {
            var trampoline = X64CodeMemory.Write(original, MaxTrampolineSize,
                                                 address => X64Relocator.Write(instructions, address, MaxTrampolineSize, false,
                                                                               out error));
            if (trampoline != 0)
                return trampoline;
        }

        logger.LogWarning($"Hook at 0x{original:X} could not be relocated ({error ?? "no free memory near it"}), calling the original may crash");
        return 0;
    }
}
